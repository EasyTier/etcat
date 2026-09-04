export const TRANSFER_CHUNK_BYTES = 64 * 1024;

export interface PayloadStream {
  read(maxLength?: number): Promise<{ data: Uint8Array; eof: boolean }>;
  write(data: Uint8Array): Promise<number>;
  shutdownWrite(): Promise<void>;
}

export type PayloadReader = (
  offset: number,
  length: number,
) => Promise<Uint8Array>;

export async function transferPayload(
  stream: PayloadStream,
  size: number,
  readChunk: PayloadReader,
  onProgress: (bytes: number) => void = () => {},
): Promise<number> {
  if (!Number.isSafeInteger(size) || size < 0) {
    throw new Error("Payload size must be a non-negative safe integer");
  }
  let offset = 0;
  while (offset < size) {
    const requested = Math.min(TRANSFER_CHUNK_BYTES, size - offset);
    const chunk = await readChunk(offset, requested);
    if (chunk.byteLength === 0 || chunk.byteLength > requested) {
      throw new Error("Payload reader returned an invalid chunk length");
    }
    await writeAll(stream, chunk);
    offset += chunk.byteLength;
    onProgress(offset);
  }
  await stream.shutdownWrite();
  for (;;) {
    const result = await stream.read(TRANSFER_CHUNK_BYTES);
    if (result.eof) {
      break;
    }
  }
  return offset;
}

export async function drainPayload(
  stream: Pick<PayloadStream, "read">,
  consume: (chunk: Uint8Array) => void | Promise<void>,
  onProgress: (bytes: number) => void = () => {},
): Promise<number> {
  let total = 0;
  for (;;) {
    const result = await stream.read(TRANSFER_CHUNK_BYTES);
    if (result.data.byteLength !== 0) {
      await consume(result.data);
      total += result.data.byteLength;
      onProgress(total);
    }
    if (result.eof) {
      return total;
    }
  }
}

export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", Uint8Array.from(bytes)),
  );
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join(
    "",
  );
}

async function writeAll(
  stream: Pick<PayloadStream, "write">,
  data: Uint8Array,
): Promise<void> {
  let offset = 0;
  while (offset < data.byteLength) {
    const written = await stream.write(data.subarray(offset));
    if (
      !Number.isInteger(written) || written <= 0 ||
      written > data.byteLength - offset
    ) {
      throw new Error(`Invalid TCP write length ${written}`);
    }
    offset += written;
  }
}
