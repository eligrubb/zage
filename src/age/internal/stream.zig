//! STREAMEncrypting and STREAMDecrypting are Io.Writer and Io.Reader interfaces that
//! encrypt and decrypt data using a variant of the STREAM[^1] chunked encryption stream.
//!
//! [^1]: https://eprint.iacr.org/2015/189
const std = @import("std");
const crypto = std.crypto;
const assert = std.debug.assert;

const File = std.fs.File;
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;
const Limit = std.Io.Limit;
const ChaCha20Poly1305 = crypto.aead.chacha_poly.ChaCha20Poly1305;
const SecretBytes = @import("zecrecy").SecretBytes;

pub const chunk_size: usize = 64 * 1024;
pub const encrypted_chunk_size: usize = chunk_size + ChaCha20Poly1305.tag_length;

pub const Nonce = struct {
    raw: u128,

    fn incrementCounter(nonce: *Nonce) void {
        nonce.raw += 1 << 8;
        // counter is 88 bits, this is unreachable
        if (nonce.raw & 0xFFFF000000000000 != 0) unreachable;
    }

    fn initFromBytes(bytes: [ChaCha20Poly1305.nonce_length]u8) Nonce {
        return .{
            .raw = std.mem.readVarInt(u128, &bytes, .big),
        };
    }

    fn setCounter(nonce: *Nonce, count: u64) void {
        nonce.raw = @as(u128, count) << 8;
    }

    fn isLast(nonce: *const Nonce) bool {
        return nonce.raw & 1 != 0;
    }

    fn setLast(nonce: *Nonce) void {
        if (nonce.isLast()) unreachable; // TODO: return proper error in this case
        nonce.raw |= 1;
    }

    fn toBytes(nonce: *Nonce) [ChaCha20Poly1305.nonce_length]u8 {
        return std.mem.asBytes(&std.mem.nativeToBig(u128, nonce.raw))[4..].*;
    }
};

/// STREAMEncrypting is an `Io.Reader` that encrypts chunks of data using the
/// STREAM variant[^1] described in the age specification. The result is
/// written to the `Io.Writer` sink.
///
/// [^1]: https://eprint.iacr.org/2015/189
pub const STREAMEncrypting = struct {
    /// ChaCha20Poly1305 key for aead file encryption
    key: SecretBytes,
    /// source Io.Reader
    source: *Reader,
    /// STREAMEncrypting Reader interface
    reader: Reader,
    /// 12-byte nonce with special format:
    /// first 11 bytes are a big endian counter that increases with each message
    /// chunk. The last byte should always be `0x00`, unless the final message
    /// chunk is being encrypted.
    nonce: Nonce = .{ .raw = 0 },
    last_chunk: bool = false,

    pub fn init(source: *Reader, key: SecretBytes) @This() {
        return .{
            .key = key,
            .source = source,
            .reader = .{
                .buffer = &[_]u8{},
                .seek = 0,
                .end = 0,
                .vtable = &.{
                    .stream = @This().stream,
                    .discard = @This().discard,
                    .rebase = @This().rebase,
                    // .readVec = @This().readVec,
                },
            },
        };
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
    ///
    /// If limit is smaller than chunk size, returns 0. Otherwise, encrypts the
    /// next chunk_size bytes from source into writer using nonce. If we reach
    /// the end of source in this chunk, the last_chunk flag is set.
    ///
    fn stream(r: *Reader, w: *Writer, limit: Limit) Reader.StreamError!usize {
        if (@intFromEnum(limit) < chunk_size) return 0;
        const e: *STREAMEncrypting = @alignCast(@fieldParentPtr("reader", r));

        var write_size = chunk_size;
        e.source.fill(chunk_size) catch {
            write_size = e.source.end - e.source.seek;
            // the last chunk can only be empty if the entire
            // message is empty
            if (write_size == 0) assert(e.nonce.raw == 0);
            e.nonce.setLast();
        };
        e.nonce.incrementCounter();

        // get our message chunk data as a slice pointing to our
        // source
        const chunk: []u8 = e.source.buffer[e.source.seek .. e.source.seek + write_size];
        e.source.seek += write_size;

        // get a slice pointing to our sink to write the ciphertext
        // and authentication tag into
        const buffer: []u8 = try w.writableSlice(write_size + ChaCha20Poly1305.tag_length);
        const ciphertext: []u8 = buffer[0..write_size];
        const tag: *[ChaCha20Poly1305.tag_length]u8 = @ptrCast(buffer[write_size .. write_size + ChaCha20Poly1305.tag_length].ptr);

        // encrypt directly to/from our sink/source
        ChaCha20Poly1305.encrypt(ciphertext, tag, chunk, &[_]u8{}, e.nonce.toBytes(), e.key.expose()[0..ChaCha20Poly1305.key_length].*);
        return write_size;
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
        const e: *STREAMEncrypting = @alignCast(@fieldParentPtr("reader", r));
        return e.source.discard(limit);
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
        const e: *STREAMEncrypting = @alignCast(@fieldParentPtr("reader", r));
        return e.source.rebase(capacity);
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
    parent_reader: *Reader,
    /// slice of decrypted but unread data backed by buffer
    chunk_data: [encrypted_chunk_size]u8,
    /// STREAMDecrypting Reader interface
    reader: Reader,
    /// 12-byte nonce with special format:
    /// first 11 bytes are a big endian counter that increases with each
    /// message chunk.
    /// The last byte should always be `0x00`, unless the final message chunk
    /// is being decrypted.
    nonce: [ChaCha20Poly1305.nonce_length]u8 = [_]u8{0} ** ChaCha20Poly1305.nonce_length,
    last_chunk: bool = false,

    pub fn init(parent: *Reader, key: [ChaCha20Poly1305.key_length]u8) @This() {
        return .{
            .key = key,
            .parent_reader = parent,
            .chunk_data = [_]u8{0} ** encrypted_chunk_size,
            .reader = .{
                // slice of decrypted but unread data backed by chunk_data
                .buffer = undefined,
                .seek = 0,
                .end = 0,
                .vtable = &.{
                    .stream = @This().stream,
                    .discard = @This().discard,
                },
            },
        };
    }

    fn stream(r: *Reader, w: *Writer, limit: Limit) Reader.StreamError!usize {
        _ = r;
        _ = w;
        _ = limit;
        @panic("not implemented");
    }

    fn discard(r: *Reader, limit: Limit) Reader.Error!usize {
        _ = r;
        _ = limit;
        @panic("not implemented");
    }

    fn readVec(r: *Reader, data: [][]u8) Reader.Error!usize { //= defaultReadVec,
        _ = r;
        _ = data;
        @panic("not implemented");
    }

    fn rebase(r: *Reader, capacity: usize) Reader.RebaseError!void { //= defaultRebase,
        _ = r;
        _ = capacity;
        @panic("not implemented");
    }
};

test "test basic STREAMEncrypting reader" {
    const allocator = std.testing.allocator;
    var key: SecretBytes = try .init(allocator, "super secret key you won't guess");
    defer key.deinit(allocator);

    const source_file = try std.fs.cwd().openFile("temp.in.txt", .{});
    defer source_file.close();
    var source_buffer: [chunk_size]u8 = undefined;
    var source = source_file.reader(&source_buffer);
    source.mode = source.mode.toStreaming();
    var encryptor: STREAMEncrypting = .init(&source.interface, key);

    var sink_file = try std.fs.cwd().openFile("temp.out.txt", .{ .mode = .write_only });
    defer sink_file.close();
    var sink_buffer: [encrypted_chunk_size]u8 = undefined;
    var sink = sink_file.writer(&sink_buffer);
    sink.mode = sink.mode.toStreaming();
    try std.testing.expectEqual(source.getSize(), try encryptor.reader.stream(&sink.interface, Limit.unlimited));
    try sink.interface.flush();

    try std.testing.expect(false);
}

test "test basic zecrecy integration" {
    const allocator = std.testing.allocator;

    var secret: SecretBytes = try .init(allocator, "secret");
    defer secret.deinit(allocator);

    var secret2: SecretBytes = try .init(allocator, "secret");
    defer secret2.deinit(allocator);

    var bad_secret: SecretBytes = try .init(allocator, "s3cret");
    defer bad_secret.deinit(allocator);

    try std.testing.expect(secret.eql(secret2));
    try std.testing.expect(secret2.eql(secret));
    try std.testing.expect(!(secret.eql(bad_secret)));
}

test "test incrementCounter" {
    var nonce: Nonce = .{ .raw = 0 };
    nonce.incrementCounter();
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0 }, &nonce.toBytes());
    nonce.incrementCounter();
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0 }, &nonce.toBytes());

    nonce = .{ .raw = 65297 }; //  decimal equivalent to [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 17 };
    nonce.incrementCounter();
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0x11 }, &nonce.toBytes());

    nonce = .{ .raw = 78918677504442992524819169024 }; // decimal equivalent to [_]u8{ 254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0 };
    nonce.incrementCounter();
    try std.testing.expectEqualSlices(u8, &[_]u8{ 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, &nonce.toBytes());
}

test "test setCounter" {
    var nonce: Nonce = .{ .raw = 0 };
    nonce.setCounter(255);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0 }, &nonce.toBytes());

    nonce.incrementCounter();
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0 }, &nonce.toBytes());

    nonce.setLast();
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1 }, &nonce.toBytes());
}

test "test initFromBytes" {
    var nonce: Nonce = .{ .raw = 0 };
    nonce.incrementCounter();
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0 }, &nonce.toBytes());
    nonce.incrementCounter();
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0 }, &nonce.toBytes());

    nonce = .initFromBytes([_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 17 });
    nonce.incrementCounter();
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0x11 }, &nonce.toBytes());

    nonce = .initFromBytes([_]u8{ 254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0 });
    nonce.incrementCounter();
    try std.testing.expectEqualSlices(u8, &[_]u8{ 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, &nonce.toBytes());
}
