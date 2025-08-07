//! STREAMEncrypting and STREAMDecrypting are Io.Writer and Io.Reader interfaces that
//! encrypt and decrypt data using a variant of the STREAM[^1] chunked encryption stream.
//!
//! [^1]: https://eprint.iacr.org/2015/189
const std = @import("std");
const crypto = std.crypto;
const assert = std.debug.assert;
const zecrecy = @import("zecrecy");

const File = std.fs.File;
const Io = std.Io;
const Reader = Io.Reader;
const Writer = Io.Writer;
const Limit = Io.Limit;
const ChaCha20Poly1305 = crypto.aead.chacha_poly.ChaCha20Poly1305;
const SecretString = zecrecy.SecretString;

pub const chunk_size = 64 * 1024;
pub const enc_chunk_size = chunk_size + ChaCha20Poly1305.tag_length;

/// STREAMEncrypting is an `Io.Writer` that encrypts chunks of data using the
/// STREAM variant[^1] described in the age specification. The result is
/// written to the `Io.Writer` sink.
///
/// [^1]: https://eprint.iacr.org/2015/189
pub const STREAMEncrypting = struct {
    /// ChaCha20Poly1305 key for aead file encryption
    key: zecrecy.Secret(u8),
    /// source Io.Reader
    source: *Io.Reader,
    /// STREAMEncrypting Reader interface
    reader: Io.Reader,
    /// 12-byte nonce with special format:
    /// first 11 bytes are a big endian counter that increases with each
    /// message chunk.
    /// The last byte should always be `0x00`, unless the final message chunk
    /// is being encrypted.
    nonce: [ChaCha20Poly1305.nonce_length]u8 = [_]u8{0} ** ChaCha20Poly1305.nonce_length,
    last_chunk: bool = false,

    pub fn init(source: *Io.Reader, key: zecrecy.Secret(u8)) @This() {
        return .{
            .key = key,
            .source = source,
            .reader = .{
                // slice of unencrypted and unwritten data
                .buffer = undefined,
                .seek = 0,
                .end = 0,
                .vtable = &.{
                    .stream = @This().stream,
                    // .drain = @This().drain,
                    // .readVec = @This().readVec,
                    // .rebase = @This().rebase,
                },
            },
        };
    }

    /// Writes the final chunk of the encrypted file.
    ///
    /// **IMPORTANT**: You *must* call this function to finish an encryption.
    /// Failure to appropriately call this function will result in a malformed,
    /// truncated ciphertext.
    pub fn finish(self: *STREAMEncrypting) void {
        self.last_chunk = true;
        self.flush();
    }

    /// Writes bytes from the internally tracked logical position to `w`.
    ///
    /// Returns the number of bytes written, which will be at minimum `0` and
    /// at most `limit`. The number returned, including zero, does not indicate
    /// end of stream.
    ///
    /// The reader's internal logical seek position moves forward in accordance
    /// with the number of bytes returned from this function.
    ///
    /// Implementations are encouraged to utilize mandatory minimum buffer
    /// sizes combined with short reads (returning a value less than `limit`)
    /// in order to minimize complexity.
    ///
    /// Although this function is usually called when `buffer` is empty, it is
    /// also called when it needs to be filled more due to the API user
    /// requesting contiguous memory. In either case, the existing buffer data
    /// should be ignored; new data written to `w`.
    ///
    /// In addition to, or instead of writing to `w`, the implementation may
    /// choose to store data in `buffer`, modifying `seek` and `end`
    /// accordingly. Implementations are encouraged to take advantage of
    /// this if it simplifies the logic.
    fn stream(r: *Reader, w: *Writer, limit: Limit) Reader.StreamError!usize {
        _ = r;
        _ = w;
        _ = limit;
        @panic("not implemented");
    }

    /// Consumes bytes from the internally tracked stream position without
    /// providing access to them.
    ///
    /// Returns the number of bytes discarded, which will be at minimum `0` and
    /// at most `limit`. The number of bytes returned, including zero, does not
    /// indicate end of stream.
    ///
    /// The reader's internal logical seek position moves forward in accordance
    /// with the number of bytes returned from this function.
    ///
    /// Implementations are encouraged to utilize mandatory minimum buffer
    /// sizes combined with short reads (returning a value less than `limit`)
    /// in order to minimize complexity.
    ///
    /// The default implementation is is based on calling `stream`, borrowing
    /// `buffer` to construct a temporary `Writer` and ignoring the written
    /// data.
    ///
    /// This function is only called when `buffer` is empty.
    fn discard(r: *Reader, limit: Limit) Reader.Error!usize { // = defaultDiscard,
        _ = r;
        _ = limit;
        @panic("not implemented");
    }

    /// Returns number of bytes written to `data`.
    ///
    /// `data` must have nonzero length. `data[0]` may have zero length, in
    /// which case the implementation must write to `Reader.buffer`.
    ///
    /// `data` may not contain an alias to `Reader.buffer`.
    ///
    /// `data` is mutable because the implementation may temporarily modify the
    /// fields in order to handle partial reads. Implementations must restore
    /// the original value before returning.
    ///
    /// Implementations may ignore `data`, writing directly to `Reader.buffer`,
    /// modifying `seek` and `end` accordingly, and returning 0 from this
    /// function. Implementations are encouraged to take advantage of this if
    /// it simplifies the logic.
    ///
    /// The default implementation calls `stream` with either `data[0]` or
    /// `Reader.buffer`, whichever is bigger.
    fn readVec(r: *Reader, data: [][]u8) Reader.Error!usize { //= defaultReadVec,
        _ = r;
        _ = data;
        @panic("not implemented");
    }

    /// Ensures `capacity` data can be buffered without rebasing.
    ///
    /// Asserts `capacity` is within buffer capacity, or that the stream ends
    /// within `capacity` bytes.
    ///
    /// Only called when `capacity` cannot be satisfied by unused capacity of
    /// `buffer`.
    ///
    /// The default implementation moves buffered data to the start of
    /// `buffer`, setting `seek` to zero, and cannot fail.
    fn rebase(r: *Reader, capacity: usize) Reader.RebaseError!void { //= defaultRebase,
        _ = r;
        _ = capacity;
        @panic("not implemented");
    }
};

/// STREAMDecrypting is an `io.AnyReader` that decrypts chunks of data using
/// the STREAM variant[^1] described in the age specification.
/// while reading the result to the source `io.AnyReader` interface.
///
/// [^1]: https://eprint.iacr.org/2015/189
pub const STREAMDecrypting = struct {
    /// ChaCha20Poly1305 key for aead file decryption
    key: [ChaCha20Poly1305.key_length]u8,
    /// source Io.AnyReader interface
    parent_reader: *Io.Reader,
    /// slice of decrypted but unread data backed by buffer
    chunk_data: [enc_chunk_size]u8,
    /// STREAMDecrypting Reader interface
    reader: Io.Reader,
    /// 12-byte nonce with special format:
    /// first 11 bytes are a big endian counter that increases with each
    /// message chunk.
    /// The last byte should always be `0x00`, unless the final message chunk
    /// is being decrypted.
    nonce: [ChaCha20Poly1305.nonce_length]u8 = [_]u8{0} ** ChaCha20Poly1305.nonce_length,
    last_chunk: bool = false,

    pub fn init(parent: *Io.Reader, key: [ChaCha20Poly1305.key_length]u8) @This() {
        return .{
            .key = key,
            .parent_reader = parent,
            .chunk_data = [_]u8{0} ** enc_chunk_size,
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

    fn stream(r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        _ = r;
        _ = w;
        _ = limit;
        @panic("not implemented");
    }

    fn discard(r: *Io.Reader, limit: Io.Limit) Io.Reader.Error!usize {
        _ = r;
        _ = limit;
        @panic("not implemented");
    }

    fn readVec(r: *Reader, data: [][]u8) Error!usize { //= defaultReadVec,
        _ = r;
        _ = data;
        @panic("not implemented");
    }

    fn rebase(r: *Reader, capacity: usize) RebaseError!void { //= defaultRebase,
        _ = r;
        _ = capacity;
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

test "test basic zecrecy integration" {
    const allocator = std.testing.allocator;

    var secret: SecretString = try .init(allocator, "secret");
    defer secret.deinit();

    var secret2: SecretString = try .init(allocator, "secret");
    defer secret2.deinit();

    var bad_secret: SecretString = try .init(allocator, "s3cret");
    defer bad_secret.deinit();

    try std.testing.expect(secret.eql(secret2));
    try std.testing.expect(secret2.eql(secret));
    try std.testing.expect(!(secret.eql(bad_secret)));
}

test "test incrementNonce" {
    var nonce = [_]u8{0} ** ChaCha20Poly1305.nonce_length;
    incrementNonce(&nonce);
    try std.testing.expectEqualSlices(u8, &nonce, &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0 });
    incrementNonce(&nonce);
    try std.testing.expectEqualSlices(u8, &nonce, &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0 });

    nonce = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 17 };
    incrementNonce(&nonce);
    try std.testing.expectEqualSlices(u8, &nonce, &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0x11 });

    nonce = [_]u8{ 254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0 };
    incrementNonce(&nonce);
    try std.testing.expectEqualSlices(u8, &nonce, &[_]u8{ 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 });
}
