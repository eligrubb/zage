const constants = @import("constants.zig");
const mem = @import("std").mem;

const Stanza = @This();

tag: []const u8, // pointer to global array, 8 bytes
args: [constants.MAX_ARGS][]const u8, // one or two args, slices, pointers to strings, 8 bytes?
buffer: []align(16) u8, // pointer to heap array, 8 bytes
body: [constants.FILE_KEY_BYTES + constants.ChaCha20Poly1305.tag_length]u8, // 48 bytes

pub fn deinit(self: Stanza, allocator: mem.Allocator) void {
    allocator.free(self.buffer);
}
