//! STREAMEncrypting and STREAMDecrypting are Io.Writer and Io.Reader interfaces that
//! encrypt and decrypt data using a variant of the STREAM[^1] chunked encryption stream.
//!
//! [^1]: https://eprint.iacr.org/2015/189
const std = @import("std");
const crypto = std.crypto;
const assert = std.debug.assert;
const zecrecy = @import("zecrecy");

const File = std.fs.File;
const Writer = std.Io.Writer;
const Reader = std.Io.Reader;
const ChaCha20Poly1305 = crypto.aead.chacha_poly.ChaCha20Poly1305;
const SecretString = zecrecy.SecretString;

pub const chunk_size = 64 * 1024;
pub const enc_chunk_size = chunk_size + ChaCha20Poly1305.tag_length;

/// STREAMEncrypting is an `Io.Writer` that encrypts chunks of data using
/// the STREAM variant[^1] described in the age specification.
/// The result to the out `Io.Writer` interface.
///
/// [^1]: https://eprint.iacr.org/2015/189
pub const STREAMEncrypting = struct {
    /// ChaCha20Poly1305 key for aead file encryption
    key: [ChaCha20Poly1305.key_length]u8,
    /// destination io.AnyWriter interface
    parent_writer: *Writer,
    /// backing data for the writer's buffer
    chunk_data: [enc_chunk_size]u8,
    /// nonce with the following format:
    nonce: [ChaCha20Poly1305.nonce_length]u8,
    writer: Writer,

    pub fn init(parent: *Writer, key: [ChaCha20Poly1305.key_length]u8) @This() {
        return .{
            .key = key,
            .parent_writer = parent,
            .chunk_data = [_]u8{0} ** enc_chunk_size,
            .nonce = [_]u8{0} ** ChaCha20Poly1305.nonce_length,
            .writer = .{
                // slice of encrypted but unwritten data backed by chunk_data
                .buffer = undefined,
                .vtable = &.{
                    .drain = @This().drain,
                    // .sendFile = @This().sendFile, TODO: determine if we need this
                    // .flush = @This().flush, TODO: determine if we need this
                },
            },
        };
    }

    /// Sends bytes to the logical sink. A write will only be sent here if it
    /// could not fit into `buffer`, or during a `flush` operation.
    ///
    /// `buffer[0..end]` is consumed first, followed by each slice of `data` in
    /// order. Elements of `data` may alias each other but may not alias
    /// `buffer`.
    ///
    /// This function modifies `Writer.end` and `Writer.buffer` in an
    /// implementation-defined manner.
    ///
    /// `data.len` must be nonzero.
    ///
    /// The last element of `data` is repeated as necessary so that it is
    /// written `splat` number of times, which may be zero.
    ///
    /// This function may not be called if the data to be written could have
    /// been stored in `buffer` instead, including when the amount of data to
    /// be written is zero and the buffer capacity is zero.
    ///
    /// Number of bytes consumed from `data` is returned, excluding bytes from
    /// `buffer`.
    ///
    /// Number of bytes returned may be zero, which does not indicate stream
    /// end. A subsequent call may return nonzero, or signal end of stream via
    /// `error.WriteFailed`.
    fn drain(w: *Writer, data: []const []const u8, splat: usize) Writer.Error!usize {
        assert(data.len > 0);
        _ = splat;

        const s: *STREAMEncrypting = @fieldParentPtr("writer", w);
        _ = s;
        @panic("not implemented");
    }

    // /// Copies contents from an open file to the logical sink. `buffer[0..end]`
    // /// is consumed first, followed by `limit` bytes from `file_reader`.
    // ///
    // /// Number of bytes logically written is returned. This excludes bytes from
    // /// `buffer` because they have already been logically written. Number of
    // /// bytes consumed from `buffer` are tracked by modifying `end`.
    // ///
    // /// Number of bytes returned may be zero, which does not indicate stream
    // /// end. A subsequent call may return nonzero, or signal end of stream via
    // /// `error.WriteFailed`. Caller may check `file_reader` state
    // /// (`File.Reader.atEnd`) to disambiguate between a zero-length read or
    // /// write, and whether the file reached the end.
    // ///
    // /// `error.Unimplemented` indicates the callee cannot offer a more
    // /// efficient implementation than the caller performing its own reads.
    // fn sendFile(w: *Writer, file_reader: *File.Reader, limit: std.io.Limit) Writer.FileError!usize {
    //     const s: *STREAMEncrypting = @fieldParentPtr("writer", w);
    // }

    // /// Consumes all remaining buffer.
    // ///
    // /// The default flush implementation calls drain repeatedly until `end` is
    // /// zero, however it is legal for implementations to manage `end`
    // /// differently. For instance, `Allocating` flush is a no-op.
    // ///
    // /// There may be subsequent calls to `drain` and `sendFile` after a `flush`
    // /// operation.
    // fn flush(w: *Writer) Writer.Error!usize {
    //     const s: *STREAMEncrypting = @fieldParentPtr("writer", w);
    // }
};

/// STREAMDecrypting is an `io.AnyReader` that decrypts chunks of data using
/// the STREAM variant[^1] described in the age specification.
/// while reading the result to the source `io.AnyReader` interface.
///
/// [^1]: https://eprint.iacr.org/2015/189
pub const STREAMDecrypting = struct {
    /// ChaCha20Poly1305 key for aead file decryption
    key: [ChaCha20Poly1305.key_length]u8,
    /// source io.AnyReader interface
    parent_reader: *Reader,
    /// slice of decrypted but unread data backed by buffer
    chunk_data: [enc_chunk_size]u8,
    /// nonce with the following format:
    nonce: [ChaCha20Poly1305.nonce_length]u8,
    reader: Reader,

    pub fn init(parent: *Reader, key: [ChaCha20Poly1305.key_length]u8) @This() {
        return .{
            .key = key,
            .parent_reader = parent,
            .chunk_data = [_]u8{0} ** enc_chunk_size,
            .nonce = [_]u8{0} ** ChaCha20Poly1305.nonce_length,
            .reader = .{
                // slice of decrypted but unread data backed by chunk_data
                .buffer = undefined,
                .vtable = &.{
                    .stream = @This().stream,
                    .discard = @This().discard,
                },
            },
        };
    }

    fn stream(r: *Reader, w: *Writer, limit: std.io.Limit) Reader.StreamError!usize {
        _ = r;
        _ = w;
        _ = limit;
        @panic("not implemented");
    }

    fn discard(r: *Reader, limit: std.io.Limit) Reader.Error!usize {
        _ = r;
        _ = limit;
        @panic("not implemented");
    }
};

fn incrementNonce(nonce: *[ChaCha20Poly1305.nonce_length]u8) void {
    assert(nonce.len == ChaCha20Poly1305.nonce_length);

    var i = nonce.len - 2;
    outer: while (i >= 0) : (i -= 1) {
        nonce.*[i] +%= 1;
        if (nonce.*[i] != 0) {
            break :outer;
        }
        // counter is 88 bits, this in unreachable
        if (i == 0) unreachable;
    }
}

test "increment nonce correctly" {
    const allocator = std.testing.allocator;

    var secret: SecretString = try .init(allocator, "secret");
    defer secret.deinit();

    try std.testing.expect(try zecrecy.eql(secret, "secret"));
    try std.testing.expect(!(try zecrecy.eql(secret, "secret2")));
}
