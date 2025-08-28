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
/// STREAM[^1] variant described in the age specification. The result is
/// written to the `Io.Writer` sink.
///
/// [^1]: https://eprint.iacr.org/2015/189
pub const STREAMEncryption = struct {
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
    mode: Mode,

    pub const Mode = enum {
        encrypting,
        decrypting,
    };

    pub fn init(source: *Reader, key: SecretBytes, comptime mode: Mode) @This() {
        return .{
            .key = key,
            .source = source,
            .mode = mode,
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
        const e: *STREAMEncryption = @alignCast(@fieldParentPtr("reader", r));

        var bytes_sourced = switch (e.mode) {
            .encrypting => chunk_size,
            .decrypting => encrypted_chunk_size,
        };

        e.source.fill(bytes_sourced) catch {
            bytes_sourced = e.source.end - e.source.seek;
            // the last chunk can only be empty if the entire
            // message is empty
            if (bytes_sourced == 0) assert(e.nonce.raw == 0);
            e.nonce.setLast();
        };
        e.nonce.incrementCounter();

        // get our input chunk data as a slice pointing
        // to our source
        const source_buffer: []u8 = e.source.buffer[e.source.seek .. e.source.seek + bytes_sourced];
        e.source.seek += bytes_sourced;

        // now lets get a slice of our sink so we have something to write our output to
        const bytes_sunk = switch (e.mode) {
            .encrypting => bytes_sourced + ChaCha20Poly1305.tag_length,
            .decrypting => bytes_sourced - ChaCha20Poly1305.tag_length,
        };

        const sink_buffer: []u8 = try w.writableSlice(bytes_sunk);

        const message: []u8 = switch (e.mode) {
            .encrypting => source_buffer,
            .decrypting => sink_buffer,
        };

        const ciphertext: []u8 = switch (e.mode) {
            .encrypting => sink_buffer[0..bytes_sourced],
            .decrypting => source_buffer[0..bytes_sunk],
        };

        const tag: *[ChaCha20Poly1305.tag_length]u8 = switch (e.mode) {
            .encrypting => @ptrCast(sink_buffer[bytes_sourced .. bytes_sourced + ChaCha20Poly1305.tag_length].ptr),
            .decrypting => @ptrCast(source_buffer[bytes_sunk .. bytes_sunk + ChaCha20Poly1305.tag_length].ptr),
        };

        switch (e.mode) {
            .encrypting => ChaCha20Poly1305.encrypt(ciphertext, tag, message, &[_]u8{}, e.nonce.toBytes(), e.key.expose()[0..ChaCha20Poly1305.key_length].*),
            .decrypting => ChaCha20Poly1305.decrypt(message, ciphertext, tag.*, &[_]u8{}, e.nonce.toBytes(), e.key.expose()[0..ChaCha20Poly1305.key_length].*) catch return error.ReadFailed,
        }

        return bytes_sourced;
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
        const e: *STREAMEncryption = @alignCast(@fieldParentPtr("reader", r));
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
        const e: *STREAMEncryption = @alignCast(@fieldParentPtr("reader", r));
        return e.source.rebase(capacity);
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
    var encryptor: STREAMEncryption = .init(&source.interface, key, .encrypting);

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
