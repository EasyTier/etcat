use std::{
    collections::{HashMap, VecDeque},
    fmt,
    fs::{self, File as StdFile, Metadata, OpenOptions},
    io::{self, Read as _, Seek as _, SeekFrom, Write as _},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, UNIX_EPOCH},
};

use directories::BaseDirs;
use russh_sftp::{
    protocol::{Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode},
    server::{Handler, StatusReply},
};

const MAX_READ_SIZE: usize = 1024 * 1024;

/// An unrestricted SFTP service running with the current user's permissions.
///
/// Relative paths start at the current user's home directory. Absolute paths
/// retain their host operating-system meaning. This is intentionally separate
/// from the capability-rooted file service used by `serve files`.
#[derive(Clone, Debug)]
pub struct FullFileService {
    home: Arc<PathBuf>,
}

impl FullFileService {
    pub fn new() -> io::Result<Self> {
        let base_dirs = BaseDirs::new().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "could not determine the current user's home directory",
            )
        })?;
        let home = base_dirs.home_dir().to_owned();
        fs::metadata(&home)?;
        Ok(Self {
            home: Arc::new(home),
        })
    }

    pub fn session(&self) -> FullFileSession {
        FullFileSession {
            home: Arc::clone(&self.home),
            state: Arc::new(Mutex::new(SessionState::default())),
        }
    }

    #[cfg(test)]
    fn with_home(home: impl Into<PathBuf>) -> Self {
        Self {
            home: Arc::new(home.into()),
        }
    }
}

/// A full-filesystem `russh-sftp` handler scoped to one SSH session.
pub struct FullFileSession {
    home: Arc<PathBuf>,
    state: Arc<Mutex<SessionState>>,
}

impl fmt::Debug for FullFileSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FullFileSession")
            .field("home", &self.home)
            .finish_non_exhaustive()
    }
}

#[derive(Default)]
struct SessionState {
    next_handle: u64,
    handles: HashMap<String, OpenHandle>,
}

enum OpenHandle {
    File {
        file: StdFile,
        readable: bool,
        writable: bool,
    },
    Directory {
        path: PathBuf,
        entries: VecDeque<File>,
    },
}

impl SessionState {
    fn insert_handle(&mut self, handle: OpenHandle) -> String {
        let id = self.next_handle;
        self.next_handle = self.next_handle.wrapping_add(1);
        let name = format!("etcat-full-{id:016x}");
        self.handles.insert(name.clone(), handle);
        name
    }
}

#[derive(Clone, Debug)]
pub struct FullFileServiceError {
    code: StatusCode,
    message: String,
}

impl FullFileServiceError {
    fn new(code: StatusCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    fn no_such_file(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NoSuchFile, message)
    }

    fn unsupported(message: impl Into<String>) -> Self {
        Self::new(StatusCode::OpUnsupported, message)
    }
}

impl fmt::Display for FullFileServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for FullFileServiceError {}

impl From<io::Error> for FullFileServiceError {
    fn from(error: io::Error) -> Self {
        let code = match error.kind() {
            io::ErrorKind::NotFound => StatusCode::NoSuchFile,
            io::ErrorKind::PermissionDenied => StatusCode::PermissionDenied,
            io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData => StatusCode::BadMessage,
            io::ErrorKind::Unsupported => StatusCode::OpUnsupported,
            _ => StatusCode::Failure,
        };
        Self::new(code, error.to_string())
    }
}

impl From<FullFileServiceError> for StatusReply {
    fn from(error: FullFileServiceError) -> Self {
        error.code.with_message(error.message)
    }
}

fn state_lock(
    state: &Mutex<SessionState>,
) -> Result<MutexGuard<'_, SessionState>, FullFileServiceError> {
    state.lock().map_err(|_| {
        FullFileServiceError::new(StatusCode::Failure, "file session state is poisoned")
    })
}

async fn blocking<T, F>(operation: F) -> Result<T, FullFileServiceError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, FullFileServiceError> + Send + 'static,
{
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|error| {
            FullFileServiceError::new(
                StatusCode::Failure,
                format!("file operation task failed: {error}"),
            )
        })?
}

fn host_path(home: &Path, path: &str) -> Result<PathBuf, FullFileServiceError> {
    if path.contains('\0') {
        return Err(FullFileServiceError::new(
            StatusCode::BadMessage,
            "file path contains NUL",
        ));
    }

    let path = PathBuf::from(path);
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(home.join(path))
    }
}

fn sftp_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn file_attributes(metadata: &Metadata) -> FileAttributes {
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt as _;

    #[cfg(unix)]
    let (permissions, uid, gid) = (metadata.mode(), Some(metadata.uid()), Some(metadata.gid()));
    #[cfg(not(unix))]
    let (permissions, uid, gid) = {
        let mut permissions = if metadata.is_symlink() {
            0o120777
        } else if metadata.is_dir() {
            0o040755
        } else {
            0o100644
        };
        if metadata.permissions().readonly() {
            permissions &= !0o222;
        }
        (permissions, None, None)
    };

    FileAttributes {
        size: Some(metadata.len()),
        uid,
        gid,
        permissions: Some(permissions),
        atime: metadata.accessed().ok().and_then(system_time_seconds),
        mtime: metadata.modified().ok().and_then(system_time_seconds),
        ..Default::default()
    }
}

fn system_time_seconds(time: std::time::SystemTime) -> Option<u32> {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u32::try_from(duration.as_secs()).ok())
}

fn status_ok(id: u32) -> Status {
    Status {
        id,
        status_code: StatusCode::Ok,
        error_message: String::new(),
        language_tag: "en-US".to_owned(),
    }
}

fn attrs_reply(id: u32, metadata: &Metadata) -> Attrs {
    Attrs {
        id,
        attrs: file_attributes(metadata),
    }
}

fn open_options(flags: OpenFlags) -> OpenOptions {
    let mut options = OpenOptions::new();
    options
        .read(flags.contains(OpenFlags::READ))
        .write(flags.contains(OpenFlags::WRITE))
        .append(flags.contains(OpenFlags::APPEND))
        .create(flags.contains(OpenFlags::CREATE))
        .truncate(flags.contains(OpenFlags::TRUNCATE));
    if flags.contains(OpenFlags::EXCLUDE) {
        options.create_new(true);
    }
    options
}

fn apply_attributes_to_file(file: &StdFile, attrs: &FileAttributes) -> io::Result<()> {
    if let Some(size) = attrs.size {
        file.set_len(size)?;
    }
    if attrs.atime.is_some() || attrs.mtime.is_some() {
        let metadata = file.metadata()?;
        let accessed = attrs.atime.map_or_else(
            || metadata.accessed(),
            |seconds| Ok(UNIX_EPOCH + Duration::from_secs(u64::from(seconds))),
        )?;
        let modified = attrs.mtime.map_or_else(
            || metadata.modified(),
            |seconds| Ok(UNIX_EPOCH + Duration::from_secs(u64::from(seconds))),
        )?;
        file.set_times(
            std::fs::FileTimes::new()
                .set_accessed(accessed)
                .set_modified(modified),
        )?;
    }
    if let Some(mode) = attrs.permissions {
        set_file_permissions(file, mode)?;
    }
    Ok(())
}

#[cfg(unix)]
fn set_file_permissions(file: &StdFile, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    file.set_permissions(fs::Permissions::from_mode(mode & 0o7777))
}

#[cfg(not(unix))]
fn set_file_permissions(file: &StdFile, mode: u32) -> io::Result<()> {
    let mut permissions = file.metadata()?.permissions();
    permissions.set_readonly(mode & 0o222 == 0);
    file.set_permissions(permissions)
}

fn apply_attributes_to_path(path: &Path, attrs: &FileAttributes) -> io::Result<()> {
    let metadata = fs::metadata(path)?;
    if attrs.size.is_some() && metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "cannot resize a directory",
        ));
    }

    if attrs.size.is_some() || attrs.atime.is_some() || attrs.mtime.is_some() {
        let file = if metadata.is_dir() {
            cap_std::fs::Dir::open_ambient_dir(path, cap_std::ambient_authority())?.into_std_file()
        } else {
            let mut options = OpenOptions::new();
            options.read(true).write(attrs.size.is_some());
            options.open(path)?
        };
        apply_attributes_to_file(
            &file,
            &FileAttributes {
                permissions: None,
                ..attrs.clone()
            },
        )?;
    }
    if let Some(mode) = attrs.permissions {
        set_path_permissions(path, mode)?;
    }
    Ok(())
}

#[cfg(unix)]
fn set_path_permissions(path: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(mode & 0o7777))
}

#[cfg(not(unix))]
fn set_path_permissions(path: &Path, mode: u32) -> io::Result<()> {
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_readonly(mode & 0o222 == 0);
    fs::set_permissions(path, permissions)
}

impl Handler for FullFileSession {
    type Error = FullFileServiceError;

    fn unimplemented(&self) -> Self::Error {
        FullFileServiceError::unsupported("SFTP operation is not supported")
    }

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        flags: OpenFlags,
        attrs: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        let path = host_path(&self.home, &filename)?;
        let state = Arc::clone(&self.state);
        blocking(move || {
            let readable = flags.contains(OpenFlags::READ);
            let writable = flags.intersects(OpenFlags::WRITE | OpenFlags::APPEND);
            if !readable && !writable {
                return Err(FullFileServiceError::new(
                    StatusCode::BadMessage,
                    "file open requires read or write access",
                ));
            }
            let file = open_options(flags).open(path)?;
            apply_attributes_to_file(&file, &attrs)?;
            let handle = state_lock(&state)?.insert_handle(OpenHandle::File {
                file,
                readable,
                writable,
            });
            Ok(Handle { id, handle })
        })
        .await
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        let state = Arc::clone(&self.state);
        blocking(move || {
            if state_lock(&state)?.handles.remove(&handle).is_none() {
                return Err(FullFileServiceError::no_such_file("unknown SFTP handle"));
            }
            Ok(status_ok(id))
        })
        .await
    }

    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<Data, Self::Error> {
        let state = Arc::clone(&self.state);
        blocking(move || {
            let mut session = state_lock(&state)?;
            let OpenHandle::File { file, readable, .. } = session
                .handles
                .get_mut(&handle)
                .ok_or_else(|| FullFileServiceError::no_such_file("unknown SFTP handle"))?
            else {
                return Err(FullFileServiceError::new(
                    StatusCode::Failure,
                    "handle is a directory",
                ));
            };
            if !*readable {
                return Err(FullFileServiceError::new(
                    StatusCode::PermissionDenied,
                    "file handle is not readable",
                ));
            }
            file.seek(SeekFrom::Start(offset))?;
            let mut data = vec![
                0;
                usize::try_from(len)
                    .unwrap_or(usize::MAX)
                    .min(MAX_READ_SIZE)
            ];
            let count = file.read(&mut data)?;
            if count == 0 {
                return Err(FullFileServiceError::new(StatusCode::Eof, "end of file"));
            }
            data.truncate(count);
            Ok(Data { id, data })
        })
        .await
    }

    async fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, Self::Error> {
        let state = Arc::clone(&self.state);
        blocking(move || {
            let mut session = state_lock(&state)?;
            let OpenHandle::File { file, writable, .. } = session
                .handles
                .get_mut(&handle)
                .ok_or_else(|| FullFileServiceError::no_such_file("unknown SFTP handle"))?
            else {
                return Err(FullFileServiceError::new(
                    StatusCode::Failure,
                    "handle is a directory",
                ));
            };
            if !*writable {
                return Err(FullFileServiceError::new(
                    StatusCode::PermissionDenied,
                    "file handle is not writable",
                ));
            }
            file.seek(SeekFrom::Start(offset))?;
            file.write_all(&data)?;
            Ok(status_ok(id))
        })
        .await
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        self.path_stat(id, path, true).await
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        self.path_stat(id, path, false).await
    }

    async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, Self::Error> {
        let state = Arc::clone(&self.state);
        blocking(move || {
            let session = state_lock(&state)?;
            let handle = session
                .handles
                .get(&handle)
                .ok_or_else(|| FullFileServiceError::no_such_file("unknown SFTP handle"))?;
            let metadata = match handle {
                OpenHandle::File { file, .. } => file.metadata()?,
                OpenHandle::Directory { path, .. } => fs::metadata(path)?,
            };
            Ok(attrs_reply(id, &metadata))
        })
        .await
    }

    async fn setstat(
        &mut self,
        id: u32,
        path: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let path = host_path(&self.home, &path)?;
        blocking(move || {
            apply_attributes_to_path(&path, &attrs)?;
            Ok(status_ok(id))
        })
        .await
    }

    async fn fsetstat(
        &mut self,
        id: u32,
        handle: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let state = Arc::clone(&self.state);
        blocking(move || {
            let session = state_lock(&state)?;
            let handle = session
                .handles
                .get(&handle)
                .ok_or_else(|| FullFileServiceError::no_such_file("unknown SFTP handle"))?;
            match handle {
                OpenHandle::File { file, .. } => apply_attributes_to_file(file, &attrs)?,
                OpenHandle::Directory { path, .. } => apply_attributes_to_path(path, &attrs)?,
            }
            Ok(status_ok(id))
        })
        .await
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        let path = host_path(&self.home, &path)?;
        let state = Arc::clone(&self.state);
        blocking(move || {
            let mut entries = VecDeque::new();
            for entry in fs::read_dir(&path)? {
                let entry = entry?;
                let name = entry.file_name().to_string_lossy().into_owned();
                let metadata = entry.path().symlink_metadata()?;
                entries.push_back(File::new(name, file_attributes(&metadata)));
            }
            let handle = state_lock(&state)?.insert_handle(OpenHandle::Directory { path, entries });
            Ok(Handle { id, handle })
        })
        .await
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        let state = Arc::clone(&self.state);
        blocking(move || {
            let mut session = state_lock(&state)?;
            let OpenHandle::Directory { entries, .. } = session
                .handles
                .get_mut(&handle)
                .ok_or_else(|| FullFileServiceError::no_such_file("unknown SFTP handle"))?
            else {
                return Err(FullFileServiceError::new(
                    StatusCode::Failure,
                    "handle is not a directory",
                ));
            };
            if entries.is_empty() {
                return Err(FullFileServiceError::new(
                    StatusCode::Eof,
                    "end of directory",
                ));
            }
            let files = entries.drain(..entries.len().min(128)).collect();
            Ok(Name { id, files })
        })
        .await
    }

    async fn remove(&mut self, id: u32, filename: String) -> Result<Status, Self::Error> {
        let path = host_path(&self.home, &filename)?;
        blocking(move || {
            fs::remove_file(path)?;
            Ok(status_ok(id))
        })
        .await
    }

    async fn mkdir(
        &mut self,
        id: u32,
        path: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let path = host_path(&self.home, &path)?;
        blocking(move || {
            fs::create_dir(&path)?;
            apply_attributes_to_path(&path, &attrs)?;
            Ok(status_ok(id))
        })
        .await
    }

    async fn rmdir(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
        let path = host_path(&self.home, &path)?;
        blocking(move || {
            fs::remove_dir(path)?;
            Ok(status_ok(id))
        })
        .await
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let path = host_path(&self.home, &path)?;
        blocking(move || {
            let path = fs::canonicalize(path)?;
            Ok(Name {
                id,
                files: vec![File::dummy(sftp_path(&path))],
            })
        })
        .await
    }

    async fn rename(
        &mut self,
        id: u32,
        oldpath: String,
        newpath: String,
    ) -> Result<Status, Self::Error> {
        let oldpath = host_path(&self.home, &oldpath)?;
        let newpath = host_path(&self.home, &newpath)?;
        blocking(move || {
            fs::rename(oldpath, newpath)?;
            Ok(status_ok(id))
        })
        .await
    }

    async fn readlink(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let path = host_path(&self.home, &path)?;
        blocking(move || {
            let target = fs::read_link(path)?;
            Ok(Name {
                id,
                files: vec![File::dummy(sftp_path(&target))],
            })
        })
        .await
    }

    async fn symlink(
        &mut self,
        id: u32,
        linkpath: String,
        targetpath: String,
    ) -> Result<Status, Self::Error> {
        let linkpath = host_path(&self.home, &linkpath)?;
        blocking(move || {
            create_symlink(Path::new(&targetpath), &linkpath)?;
            Ok(status_ok(id))
        })
        .await
    }
}

impl FullFileSession {
    async fn path_stat(
        &self,
        id: u32,
        path: String,
        follow: bool,
    ) -> Result<Attrs, FullFileServiceError> {
        let path = host_path(&self.home, &path)?;
        blocking(move || {
            let metadata = if follow {
                fs::metadata(path)?
            } else {
                fs::symlink_metadata(path)?
            };
            Ok(attrs_reply(id, &metadata))
        })
        .await
    }
}

#[cfg(unix)]
fn create_symlink(target: &Path, link: &Path) -> io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(windows)]
fn create_symlink(target: &Path, link: &Path) -> io::Result<()> {
    use std::os::windows::fs::{symlink_dir, symlink_file};

    let target_for_metadata = if target.is_absolute() {
        target.to_owned()
    } else {
        link.parent().unwrap_or_else(|| Path::new(".")).join(target)
    };
    if fs::metadata(target_for_metadata).is_ok_and(|metadata| metadata.is_dir()) {
        symlink_dir(target, link)
    } else {
        symlink_file(target, link)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tokio::io::AsyncWriteExt as _;

    use super::*;

    #[test]
    fn relative_paths_start_at_home_and_absolute_paths_do_not() {
        let home = tempfile::tempdir().unwrap();
        let absolute = tempfile::NamedTempFile::new().unwrap();

        assert_eq!(
            host_path(home.path(), "documents/file.txt").unwrap(),
            home.path().join("documents/file.txt")
        );
        assert_eq!(
            host_path(home.path(), absolute.path().to_str().unwrap()).unwrap(),
            absolute.path()
        );
        assert!(host_path(home.path(), "bad\0path").is_err());
    }

    #[tokio::test]
    async fn serves_relative_and_absolute_paths_over_sftp() {
        let home = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        fs::write(outside.path(), b"outside").unwrap();

        let service = FullFileService::with_home(home.path());
        let (server_stream, client_stream) = tokio::io::duplex(256 * 1024);
        russh_sftp::server::run(server_stream, service.session()).await;
        let client = russh_sftp::client::SftpSession::new(client_stream)
            .await
            .unwrap();

        let mut uploaded = client.create("relative.txt").await.unwrap();
        uploaded.write_all(b"relative").await.unwrap();
        uploaded.shutdown().await.unwrap();
        assert_eq!(
            fs::read(home.path().join("relative.txt")).unwrap(),
            b"relative"
        );
        assert_eq!(client.metadata("relative.txt").await.unwrap().len(), 8);
        let opened = client
            .open_with_flags("relative.txt", OpenFlags::READ | OpenFlags::WRITE)
            .await
            .unwrap();
        let mut metadata = opened.metadata().await.unwrap();
        metadata.size = Some(4);
        opened.set_metadata(metadata).await.unwrap();
        opened.close().await.unwrap();
        assert_eq!(fs::read(home.path().join("relative.txt")).unwrap(), b"rela");

        let canonical_home = fs::canonicalize(home.path()).unwrap();
        assert_eq!(
            client.canonicalize(".").await.unwrap(),
            sftp_path(&canonical_home)
        );

        let absolute_path = outside.path().to_string_lossy().into_owned();
        assert_eq!(client.read(absolute_path).await.unwrap(), b"outside");

        client.create_dir("directory").await.unwrap();
        client
            .rename("relative.txt", "directory/renamed.txt")
            .await
            .unwrap();
        let entries: Vec<_> = client.read_dir("directory").await.unwrap().collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].file_name(), "renamed.txt");
        client.remove_file("directory/renamed.txt").await.unwrap();
        client.remove_dir("directory").await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn serves_symbolic_links_over_sftp() {
        let home = tempfile::tempdir().unwrap();
        fs::write(home.path().join("target.txt"), b"target").unwrap();

        let service = FullFileService::with_home(home.path());
        let (server_stream, client_stream) = tokio::io::duplex(256 * 1024);
        russh_sftp::server::run(server_stream, service.session()).await;
        let client = russh_sftp::client::SftpSession::new(client_stream)
            .await
            .unwrap();

        client.symlink("link.txt", "target.txt").await.unwrap();
        assert_eq!(client.read_link("link.txt").await.unwrap(), "target.txt");
        assert!(
            client
                .symlink_metadata("link.txt")
                .await
                .unwrap()
                .is_symlink()
        );
        assert_eq!(client.read("link.txt").await.unwrap(), b"target");
    }
}
