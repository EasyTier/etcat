use std::{
    collections::{HashMap, VecDeque},
    fmt,
    io::{self, Read as _, Seek as _, SeekFrom, Write as _},
    path::{Path, PathBuf},
    str::FromStr,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use cap_std::{
    ambient_authority,
    fs::{Dir, File as CapFile, Metadata, OpenOptions},
};
use rand::{RngCore as _, rngs::OsRng};
use russh_sftp::{
    protocol::{Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode},
    server::{Handler, StatusReply},
};

/// Access policy for a rooted file service.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum FileMode {
    /// Clients can list, inspect, and download files.
    #[default]
    ReadOnly,
    /// Clients have full read-write access below the configured root.
    ReadWrite,
    /// Flat write-only drop box. Every upload receives a server-chosen name.
    WriteOnly,
    /// Recursive write-only drop box. Directories may be created and inspected.
    WriteOnlyRecursive,
}

impl FileMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "ro",
            Self::ReadWrite => "rw",
            Self::WriteOnly => "wo",
            Self::WriteOnlyRecursive => "wo+",
        }
    }

    const fn is_write_only(self) -> bool {
        matches!(self, Self::WriteOnly | Self::WriteOnlyRecursive)
    }
}

impl fmt::Display for FileMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for FileMode {
    type Err = ParseFileModeError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "ro" => Ok(Self::ReadOnly),
            "rw" => Ok(Self::ReadWrite),
            "wo" => Ok(Self::WriteOnly),
            "wo+" => Ok(Self::WriteOnlyRecursive),
            _ => Err(ParseFileModeError(value.to_owned())),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParseFileModeError(String);

impl fmt::Display for ParseFileModeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid file mode {:?}; expected ro, rw, wo, or wo+",
            self.0
        )
    }
}

impl std::error::Error for ParseFileModeError {}

/// Capability-rooted file service configuration.
#[derive(Clone)]
pub struct FileService {
    root: Arc<Dir>,
    mode: FileMode,
}

impl fmt::Debug for FileService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileService")
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

impl FileService {
    /// Opens `root` once as a capability. All future client paths are resolved
    /// relative to this descriptor, including on platforms where paths can be
    /// renamed while a session is active.
    pub fn new(root: impl AsRef<Path>, mode: FileMode) -> io::Result<Self> {
        Ok(Self {
            root: Arc::new(Dir::open_ambient_dir(root, ambient_authority())?),
            mode,
        })
    }

    /// Creates an isolated handler for one SFTP session. Drop-box visibility
    /// and post-upload metadata access never carry over to another session.
    pub fn session(&self) -> FileSession {
        FileSession {
            root: Arc::clone(&self.root),
            mode: self.mode,
            state: Arc::new(Mutex::new(SessionState::default())),
        }
    }
}

/// A `russh-sftp` handler scoped to one SSH session.
pub struct FileSession {
    root: Arc<Dir>,
    mode: FileMode,
    state: Arc<Mutex<SessionState>>,
}

impl fmt::Debug for FileSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileSession")
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

#[derive(Default)]
struct SessionState {
    next_handle: u64,
    handles: HashMap<String, OpenHandle>,
    aliases: HashMap<PathBuf, PathBuf>,
}

enum OpenHandle {
    File {
        file: CapFile,
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
        let name = format!("etcat-{id:016x}");
        self.handles.insert(name.clone(), handle);
        name
    }

    fn actual_path(&self, visible: &Path) -> Option<PathBuf> {
        self.aliases.get(visible).cloned()
    }

    fn mark_owned(&mut self, visible: PathBuf, actual: PathBuf) {
        self.aliases.insert(visible, actual);
    }
}

#[derive(Clone, Debug)]
pub struct FileServiceError {
    code: StatusCode,
    message: String,
}

impl FileServiceError {
    fn new(code: StatusCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    fn permission(message: impl Into<String>) -> Self {
        Self::new(StatusCode::PermissionDenied, message)
    }

    fn no_such_file(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NoSuchFile, message)
    }

    fn unsupported(message: impl Into<String>) -> Self {
        Self::new(StatusCode::OpUnsupported, message)
    }
}

impl fmt::Display for FileServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for FileServiceError {}

impl From<io::Error> for FileServiceError {
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

impl From<FileServiceError> for StatusReply {
    fn from(error: FileServiceError) -> Self {
        error.code.with_message(error.message)
    }
}

fn state_lock(
    state: &Mutex<SessionState>,
) -> Result<MutexGuard<'_, SessionState>, FileServiceError> {
    state
        .lock()
        .map_err(|_| FileServiceError::new(StatusCode::Failure, "file session state is poisoned"))
}

async fn blocking<T, F>(operation: F) -> Result<T, FileServiceError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, FileServiceError> + Send + 'static,
{
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|error| {
            FileServiceError::new(
                StatusCode::Failure,
                format!("file operation task failed: {error}"),
            )
        })?
}

/// Converts an SFTP path into a path relative to the capability root.
/// Leading slashes denote the virtual root and never grant ambient access.
fn rooted_path(path: &str) -> Result<PathBuf, FileServiceError> {
    if path.contains('\0') {
        return Err(FileServiceError::new(
            StatusCode::BadMessage,
            "file path contains NUL",
        ));
    }

    let mut result = PathBuf::new();
    for component in path.replace('\\', "/").split('/') {
        match component {
            "" | "." => {}
            ".." => {
                return Err(FileServiceError::permission(
                    "parent path components are not allowed",
                ));
            }
            component
                if component.len() == 2
                    && component.as_bytes()[0].is_ascii_alphabetic()
                    && component.as_bytes()[1] == b':' =>
            {
                return Err(FileServiceError::permission(
                    "host absolute paths are not allowed",
                ));
            }
            component => result.push(component),
        }
    }
    Ok(result)
}

fn virtual_path(path: &Path) -> String {
    if path.as_os_str().is_empty() {
        return "/".to_owned();
    }
    format!("/{}", path.to_string_lossy().replace('\\', "/"))
}

fn root_metadata(root: &Dir, path: &Path, follow: bool) -> io::Result<Metadata> {
    if path.as_os_str().is_empty() {
        root.dir_metadata()
    } else if follow {
        root.metadata(path)
    } else {
        root.symlink_metadata(path)
    }
}

fn file_attributes(metadata: &Metadata) -> FileAttributes {
    #[cfg(unix)]
    use cap_std::fs::MetadataExt as _;

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
        atime: metadata.accessed().ok().and_then(cap_time_seconds),
        mtime: metadata.modified().ok().and_then(cap_time_seconds),
        ..Default::default()
    }
}

fn cap_time_seconds(time: cap_std::time::SystemTime) -> Option<u32> {
    time.into_std()
        .duration_since(UNIX_EPOCH)
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

fn unique_upload_path(requested: &Path) -> Result<PathBuf, FileServiceError> {
    let file_name = requested
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| FileServiceError::permission("an upload must have a file name"))?;
    let file_path = Path::new(file_name);
    let extension = file_path
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| format!(".{value}"))
        .unwrap_or_default();
    let stem = file_path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or(file_name);
    let mut random = [0_u8; 8];
    OsRng.try_fill_bytes(&mut random).map_err(|error| {
        FileServiceError::new(
            StatusCode::Failure,
            format!("failed to generate an upload name: {error}"),
        )
    })?;
    let suffix = u64::from_be_bytes(random);
    let timestamp = utc_timestamp(SystemTime::now())?;
    let unique_name = format!("{stem}.{timestamp}.{suffix:016x}{extension}");
    Ok(
        if let Some(parent) = requested
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            parent.join(&unique_name)
        } else {
            PathBuf::from(unique_name)
        },
    )
}

fn utc_timestamp(time: SystemTime) -> Result<String, FileServiceError> {
    let seconds = time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| FileServiceError::new(StatusCode::Failure, "system clock precedes 1970"))?
        .as_secs();
    let days = i64::try_from(seconds / 86_400)
        .map_err(|_| FileServiceError::new(StatusCode::Failure, "system clock is out of range"))?;
    let seconds_of_day = seconds % 86_400;
    let (year, month, day) = civil_date_from_days(days);
    let hour = seconds_of_day / 3_600;
    let minute = seconds_of_day % 3_600 / 60;
    let second = seconds_of_day % 60;
    Ok(format!(
        "{year:04}{month:02}{day:02}{hour:02}{minute:02}{second:02}"
    ))
}

// Howard Hinnant's civil-from-days transform, with day zero at 1970-01-01.
fn civil_date_from_days(days_since_epoch: i64) -> (i64, i64, i64) {
    let days = days_since_epoch + 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (year, month, day)
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

fn apply_attributes_to_file(file: &CapFile, attrs: &FileAttributes) -> io::Result<()> {
    if let Some(size) = attrs.size {
        file.set_len(size)?;
    }
    if attrs.atime.is_some() || attrs.mtime.is_some() {
        let metadata = file.metadata()?;
        let accessed = attrs.atime.map_or_else(
            || metadata.accessed().map(cap_std::time::SystemTime::into_std),
            |seconds| Ok(UNIX_EPOCH + Duration::from_secs(u64::from(seconds))),
        )?;
        let modified = attrs.mtime.map_or_else(
            || metadata.modified().map(cap_std::time::SystemTime::into_std),
            |seconds| Ok(UNIX_EPOCH + Duration::from_secs(u64::from(seconds))),
        )?;
        file.try_clone()?.into_std().set_times(
            std::fs::FileTimes::new()
                .set_accessed(accessed)
                .set_modified(modified),
        )?;
    }
    if let Some(permissions) = attrs.permissions {
        set_file_permissions(file, permissions)?;
    }
    Ok(())
}

#[cfg(unix)]
fn set_file_permissions(file: &CapFile, mode: u32) -> io::Result<()> {
    use cap_std::fs::PermissionsExt as _;
    file.set_permissions(cap_std::fs::Permissions::from_mode(mode & 0o7777))
}

#[cfg(not(unix))]
fn set_file_permissions(file: &CapFile, mode: u32) -> io::Result<()> {
    let mut permissions = file.metadata()?.permissions();
    permissions.set_readonly(mode & 0o222 == 0);
    file.set_permissions(permissions)
}

fn apply_attributes_to_path(root: &Dir, path: &Path, attrs: &FileAttributes) -> io::Result<()> {
    let metadata = root_metadata(root, path, true)?;
    if attrs.size.is_some() && metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "cannot resize a directory",
        ));
    }

    if metadata.is_dir() {
        if attrs.atime.is_some() || attrs.mtime.is_some() {
            let directory = if path.as_os_str().is_empty() {
                root.try_clone()?
            } else {
                root.open_dir(path)?
            };
            let file = CapFile::from_std(directory.into_std_file());
            apply_attributes_to_file(
                &file,
                &FileAttributes {
                    size: None,
                    permissions: None,
                    ..attrs.clone()
                },
            )?;
        }
        if let Some(permissions) = attrs.permissions {
            set_path_permissions(root, path, permissions)?;
        }
        return Ok(());
    }

    let mut options = OpenOptions::new();
    if attrs.size.is_some() {
        options.write(true);
    } else {
        options.read(true);
    }
    let file = root.open_with(path, &options)?;
    apply_attributes_to_file(
        &file,
        &FileAttributes {
            permissions: None,
            ..attrs.clone()
        },
    )?;
    if let Some(permissions) = attrs.permissions {
        set_path_permissions(root, path, permissions)?;
    }
    Ok(())
}

#[cfg(unix)]
fn set_path_permissions(root: &Dir, path: &Path, mode: u32) -> io::Result<()> {
    use cap_std::fs::PermissionsExt as _;
    root.set_permissions(path, cap_std::fs::Permissions::from_mode(mode & 0o7777))
}

#[cfg(not(unix))]
fn set_path_permissions(root: &Dir, path: &Path, mode: u32) -> io::Result<()> {
    let mut permissions = root_metadata(root, path, true)?.permissions();
    permissions.set_readonly(mode & 0o222 == 0);
    root.set_permissions(path, permissions)
}

impl Handler for FileSession {
    type Error = FileServiceError;

    fn unimplemented(&self) -> Self::Error {
        FileServiceError::unsupported("SFTP operation is not supported")
    }

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        flags: OpenFlags,
        _attrs: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        let path = rooted_path(&filename)?;
        let root = Arc::clone(&self.root);
        let state = Arc::clone(&self.state);
        let mode = self.mode;
        blocking(move || {
            if mode == FileMode::ReadOnly
                && flags.intersects(
                    OpenFlags::WRITE
                        | OpenFlags::APPEND
                        | OpenFlags::CREATE
                        | OpenFlags::TRUNCATE
                        | OpenFlags::EXCLUDE,
                )
            {
                return Err(FileServiceError::permission("file service is read-only"));
            }

            let readable = flags.contains(OpenFlags::READ);
            let writable = flags.intersects(OpenFlags::WRITE | OpenFlags::APPEND);
            let (actual, file) = if mode.is_write_only() {
                if readable || !writable || !flags.contains(OpenFlags::CREATE) {
                    return Err(FileServiceError::permission(
                        "drop-box uploads must create a write-only file",
                    ));
                }
                if path.as_os_str().is_empty()
                    || (mode == FileMode::WriteOnly
                        && path.parent().is_some_and(|p| !p.as_os_str().is_empty()))
                {
                    return Err(FileServiceError::permission(
                        "flat drop-box uploads must use a root-level file name",
                    ));
                }

                let mut actual = if mode == FileMode::WriteOnly {
                    unique_upload_path(&path)?
                } else {
                    path.clone()
                };
                let mut options = OpenOptions::new();
                options.write(true).create_new(true);
                let file = match root.open_with(&actual, &options) {
                    Ok(file) => file,
                    Err(error)
                        if mode == FileMode::WriteOnlyRecursive
                            && error.kind() == io::ErrorKind::AlreadyExists =>
                    {
                        actual = unique_upload_path(&path)?;
                        root.open_with(&actual, &options)?
                    }
                    Err(error) => return Err(error.into()),
                };
                (actual, file)
            } else {
                if !readable && !writable {
                    return Err(FileServiceError::new(
                        StatusCode::BadMessage,
                        "file open requires read or write access",
                    ));
                }
                (path.clone(), root.open_with(&path, &open_options(flags))?)
            };

            let mut session = state_lock(&state)?;
            if mode.is_write_only() {
                session.mark_owned(path, actual.clone());
            }
            let handle = session.insert_handle(OpenHandle::File {
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
            let removed = state_lock(&state)?.handles.remove(&handle);
            if removed.is_none() {
                return Err(FileServiceError::no_such_file("unknown SFTP handle"));
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
                .ok_or_else(|| FileServiceError::no_such_file("unknown SFTP handle"))?
            else {
                return Err(FileServiceError::new(
                    StatusCode::Failure,
                    "handle is a directory",
                ));
            };
            if !*readable {
                return Err(FileServiceError::permission("file handle is not readable"));
            }
            file.seek(SeekFrom::Start(offset))?;
            let mut data = vec![0; len as usize];
            let count = file.read(&mut data)?;
            if count == 0 {
                return Err(FileServiceError::new(StatusCode::Eof, "end of file"));
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
                .ok_or_else(|| FileServiceError::no_such_file("unknown SFTP handle"))?
            else {
                return Err(FileServiceError::new(
                    StatusCode::Failure,
                    "handle is a directory",
                ));
            };
            if !*writable {
                return Err(FileServiceError::permission("file handle is not writable"));
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
        let root = Arc::clone(&self.root);
        let state = Arc::clone(&self.state);
        blocking(move || {
            let session = state_lock(&state)?;
            let handle = session
                .handles
                .get(&handle)
                .ok_or_else(|| FileServiceError::no_such_file("unknown SFTP handle"))?;
            let metadata = match handle {
                OpenHandle::File { file, .. } => file.metadata()?,
                OpenHandle::Directory { path, .. } => root_metadata(&root, path, true)?,
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
        let path = rooted_path(&path)?;
        let root = Arc::clone(&self.root);
        let state = Arc::clone(&self.state);
        let mode = self.mode;
        blocking(move || {
            if mode == FileMode::ReadOnly {
                return Err(FileServiceError::permission("file service is read-only"));
            }
            let actual = if mode.is_write_only() {
                state_lock(&state)?.actual_path(&path).ok_or_else(|| {
                    FileServiceError::permission("path was not created by this session")
                })?
            } else {
                path
            };
            apply_attributes_to_path(&root, &actual, &attrs)?;
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
        if self.mode == FileMode::ReadOnly {
            return Err(FileServiceError::permission("file service is read-only"));
        }
        let root = Arc::clone(&self.root);
        let state = Arc::clone(&self.state);
        blocking(move || {
            let session = state_lock(&state)?;
            let handle = session
                .handles
                .get(&handle)
                .ok_or_else(|| FileServiceError::no_such_file("unknown SFTP handle"))?;
            match handle {
                OpenHandle::File { file, .. } => apply_attributes_to_file(file, &attrs)?,
                OpenHandle::Directory { path, .. } => {
                    apply_attributes_to_path(&root, path, &attrs)?;
                }
            }
            Ok(status_ok(id))
        })
        .await
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        if self.mode.is_write_only() {
            return Err(FileServiceError::permission(
                "drop-box directories cannot be listed",
            ));
        }
        let path = rooted_path(&path)?;
        let root = Arc::clone(&self.root);
        let state = Arc::clone(&self.state);
        blocking(move || {
            let directory = if path.as_os_str().is_empty() {
                root.try_clone()?
            } else {
                root.open_dir(&path)?
            };
            let mut entries = VecDeque::new();
            for entry in directory.entries()? {
                let entry = entry?;
                let name = entry.file_name().to_string_lossy().into_owned();
                let metadata = root_metadata(&root, &path.join(&name), false)?;
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
                .ok_or_else(|| FileServiceError::no_such_file("unknown SFTP handle"))?
            else {
                return Err(FileServiceError::new(
                    StatusCode::Failure,
                    "handle is not a directory",
                ));
            };
            if entries.is_empty() {
                return Err(FileServiceError::new(StatusCode::Eof, "end of directory"));
            }
            let files = entries.drain(..entries.len().min(128)).collect();
            Ok(Name { id, files })
        })
        .await
    }

    async fn remove(&mut self, id: u32, filename: String) -> Result<Status, Self::Error> {
        self.mutate_path(id, filename, |root, path| root.remove_file(path))
            .await
    }

    async fn mkdir(
        &mut self,
        id: u32,
        path: String,
        _attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let path = rooted_path(&path)?;
        let root = Arc::clone(&self.root);
        let state = Arc::clone(&self.state);
        let mode = self.mode;
        blocking(move || {
            match mode {
                FileMode::ReadOnly | FileMode::WriteOnly => {
                    return Err(FileServiceError::permission(
                        "this file mode does not allow directories to be created",
                    ));
                }
                FileMode::ReadWrite | FileMode::WriteOnlyRecursive => {}
            }
            if path.as_os_str().is_empty() {
                return Err(FileServiceError::permission(
                    "cannot create the service root",
                ));
            }
            root.create_dir(&path)?;
            if mode == FileMode::WriteOnlyRecursive {
                state_lock(&state)?.mark_owned(path.clone(), path);
            }
            Ok(status_ok(id))
        })
        .await
    }

    async fn rmdir(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
        self.mutate_path(id, path, |root, path| root.remove_dir(path))
            .await
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let path = rooted_path(&path)?;
        Ok(Name {
            id,
            files: vec![File::dummy(virtual_path(&path))],
        })
    }

    async fn rename(
        &mut self,
        id: u32,
        oldpath: String,
        newpath: String,
    ) -> Result<Status, Self::Error> {
        if self.mode != FileMode::ReadWrite {
            return Err(FileServiceError::permission(
                "file mode does not allow rename",
            ));
        }
        let oldpath = rooted_path(&oldpath)?;
        let newpath = rooted_path(&newpath)?;
        let root = Arc::clone(&self.root);
        blocking(move || {
            root.rename(oldpath, &root, newpath)?;
            Ok(status_ok(id))
        })
        .await
    }

    async fn readlink(&mut self, _id: u32, _path: String) -> Result<Name, Self::Error> {
        Err(FileServiceError::unsupported(
            "symbolic links are disabled in rooted file services",
        ))
    }

    async fn symlink(
        &mut self,
        _id: u32,
        _linkpath: String,
        _targetpath: String,
    ) -> Result<Status, Self::Error> {
        Err(FileServiceError::unsupported(
            "symbolic links are disabled in rooted file services",
        ))
    }
}

impl FileSession {
    async fn path_stat(
        &self,
        id: u32,
        path: String,
        follow: bool,
    ) -> Result<Attrs, FileServiceError> {
        let path = rooted_path(&path)?;
        let root = Arc::clone(&self.root);
        let state = Arc::clone(&self.state);
        let mode = self.mode;
        blocking(move || {
            let actual = if mode.is_write_only() {
                if let Some(actual) = state_lock(&state)?.actual_path(&path) {
                    actual
                } else if path.as_os_str().is_empty() {
                    path
                } else if mode == FileMode::WriteOnlyRecursive {
                    let metadata = root_metadata(&root, &path, follow)
                        .map_err(|_| FileServiceError::no_such_file("path is not visible"))?;
                    if !metadata.is_dir() {
                        return Err(FileServiceError::no_such_file("path is not visible"));
                    }
                    return Ok(attrs_reply(id, &metadata));
                } else {
                    return Err(FileServiceError::no_such_file("path is not visible"));
                }
            } else {
                path
            };
            Ok(attrs_reply(id, &root_metadata(&root, &actual, follow)?))
        })
        .await
    }

    async fn mutate_path<F>(
        &self,
        id: u32,
        path: String,
        operation: F,
    ) -> Result<Status, FileServiceError>
    where
        F: FnOnce(&Dir, &Path) -> io::Result<()> + Send + 'static,
    {
        if self.mode != FileMode::ReadWrite {
            return Err(FileServiceError::permission(
                "file mode does not allow this operation",
            ));
        }
        let path = rooted_path(&path)?;
        let root = Arc::clone(&self.root);
        blocking(move || {
            operation(&root, &path)?;
            Ok(status_ok(id))
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, io::ErrorKind};

    use tokio::io::{AsyncWriteExt as _, duplex};

    use super::*;

    fn flags(values: &[OpenFlags]) -> OpenFlags {
        values
            .iter()
            .copied()
            .fold(OpenFlags::empty(), |all, flag| all | flag)
    }

    async fn upload(
        session: &mut FileSession,
        path: &str,
        contents: &[u8],
    ) -> Result<(), FileServiceError> {
        let opened = session
            .open(
                1,
                path.to_owned(),
                flags(&[OpenFlags::WRITE, OpenFlags::CREATE, OpenFlags::TRUNCATE]),
                FileAttributes::default(),
            )
            .await?;
        session
            .write(2, opened.handle.clone(), 0, contents.to_vec())
            .await?;
        session.close(3, opened.handle).await?;
        Ok(())
    }

    #[test]
    fn parses_file_modes_and_formats_timestamps() {
        for (text, mode) in [
            ("ro", FileMode::ReadOnly),
            ("rw", FileMode::ReadWrite),
            ("wo", FileMode::WriteOnly),
            ("wo+", FileMode::WriteOnlyRecursive),
        ] {
            assert_eq!(text.parse::<FileMode>().unwrap(), mode);
            assert_eq!(mode.to_string(), text);
        }
        assert!("read-only".parse::<FileMode>().is_err());
        assert_eq!(
            utc_timestamp(UNIX_EPOCH + Duration::from_secs(951_827_696)).unwrap(),
            "20000229123456"
        );
    }

    #[tokio::test]
    async fn read_only_and_read_write_enforce_their_permissions() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("existing.txt"), "existing").unwrap();

        let mut read_only = FileService::new(directory.path(), FileMode::ReadOnly)
            .unwrap()
            .session();
        let opened = read_only
            .open(
                1,
                "existing.txt".into(),
                OpenFlags::READ,
                FileAttributes::default(),
            )
            .await
            .unwrap();
        assert_eq!(
            read_only.read(2, opened.handle, 0, 32).await.unwrap().data,
            b"existing"
        );
        assert!(upload(&mut read_only, "denied.txt", b"no").await.is_err());

        let mut read_write = FileService::new(directory.path(), FileMode::ReadWrite)
            .unwrap()
            .session();
        upload(&mut read_write, "new.txt", b"new").await.unwrap();
        read_write
            .rename(3, "new.txt".into(), "renamed.txt".into())
            .await
            .unwrap();
        assert_eq!(
            fs::read(directory.path().join("renamed.txt")).unwrap(),
            b"new"
        );
        read_write.remove(4, "renamed.txt".into()).await.unwrap();
    }

    #[tokio::test]
    async fn serves_a_complete_sftp_protocol_round_trip() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("existing.txt"), "existing").unwrap();
        let service = FileService::new(directory.path(), FileMode::ReadWrite).unwrap();
        let (server_stream, client_stream) = duplex(256 * 1024);
        russh_sftp::server::run(server_stream, service.session()).await;
        let client = russh_sftp::client::SftpSession::new(client_stream)
            .await
            .unwrap();

        assert_eq!(client.read("/existing.txt").await.unwrap(), b"existing");
        let mut uploaded = client.create("/uploaded.txt").await.unwrap();
        uploaded.write_all(b"uploaded").await.unwrap();
        uploaded.shutdown().await.unwrap();
        assert_eq!(
            fs::read(directory.path().join("uploaded.txt")).unwrap(),
            b"uploaded"
        );
        assert!(
            client
                .read_dir("/")
                .await
                .unwrap()
                .any(|entry| entry.file_name() == "uploaded.txt")
        );
        client.close().await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn capability_root_rejects_parent_and_symlink_escape() {
        use std::os::unix::fs::symlink;

        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("root");
        fs::create_dir(&root).unwrap();
        fs::write(parent.path().join("secret"), "secret").unwrap();
        symlink(parent.path().join("secret"), root.join("escape")).unwrap();
        let mut session = FileService::new(&root, FileMode::ReadWrite)
            .unwrap()
            .session();

        assert!(
            session
                .open(
                    1,
                    "../secret".into(),
                    OpenFlags::READ,
                    FileAttributes::default()
                )
                .await
                .is_err()
        );
        assert!(
            session
                .open(
                    2,
                    "escape".into(),
                    OpenFlags::READ,
                    FileAttributes::default()
                )
                .await
                .is_err()
        );
        assert!(
            session
                .symlink(3, "link".into(), "../secret".into())
                .await
                .is_err()
        );
        assert!(session.readlink(4, "escape".into()).await.is_err());
    }

    #[tokio::test]
    async fn flat_drop_box_hides_names_and_tracks_only_its_session() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("existing.txt"), "original").unwrap();
        let service = FileService::new(directory.path(), FileMode::WriteOnly).unwrap();
        let mut session = service.session();

        upload(&mut session, "existing.txt", b"first")
            .await
            .unwrap();
        upload(&mut session, "existing.txt", b"second")
            .await
            .unwrap();
        assert_eq!(
            fs::read(directory.path().join("existing.txt")).unwrap(),
            b"original"
        );
        let uploads = fs::read_dir(directory.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                name != "existing.txt" && name.starts_with("existing.")
            })
            .count();
        assert_eq!(uploads, 2);
        session.stat(5, "existing.txt".into()).await.unwrap();
        assert!(session.stat(6, "subdir".into()).await.is_err());
        assert!(session.opendir(7, "/".into()).await.is_err());
        assert!(upload(&mut session, "sub/file", b"nested").await.is_err());

        let mut other_session = service.session();
        assert!(other_session.stat(8, "existing.txt".into()).await.is_err());
    }

    #[tokio::test]
    async fn recursive_drop_box_preserves_free_names_and_allows_directories() {
        let directory = tempfile::tempdir().unwrap();
        fs::create_dir(directory.path().join("existing-dir")).unwrap();
        let service = FileService::new(directory.path(), FileMode::WriteOnlyRecursive).unwrap();
        let mut session = service.session();

        session.stat(1, "existing-dir".into()).await.unwrap();
        upload(&mut session, "drop.txt", b"first").await.unwrap();
        upload(&mut session, "drop.txt", b"second").await.unwrap();
        assert_eq!(
            fs::read(directory.path().join("drop.txt")).unwrap(),
            b"first"
        );
        assert_eq!(
            fs::read_dir(directory.path())
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| {
                    let name = entry.file_name();
                    let name = name.to_string_lossy();
                    name != "drop.txt" && name.starts_with("drop.")
                })
                .count(),
            1
        );
        session
            .mkdir(2, "new-dir".into(), FileAttributes::default())
            .await
            .unwrap();
        upload(&mut session, "new-dir/nested", b"nested")
            .await
            .unwrap();
        assert_eq!(
            fs::read(directory.path().join("new-dir/nested")).unwrap(),
            b"nested"
        );
        assert!(session.opendir(3, "/".into()).await.is_err());
        assert!(
            session
                .open(
                    4,
                    "drop.txt".into(),
                    OpenFlags::READ,
                    FileAttributes::default()
                )
                .await
                .is_err()
        );

        let error = root_metadata(&service.root, Path::new("missing"), true).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotFound);
    }
}
