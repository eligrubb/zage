const constants = @import("constants.zig");
const mem = @import("std").mem;
const Stanza = @This();

tag: []const u8,
args: [constants.MAX_ARGS][]const u8,
body: [constants.FILE_KEY_BYTES + constants.ChaCha20Poly1305.tag_length]u8,
buffer: []align(16) u8,

pub fn deinit(self: *Stanza, allocator: mem.Allocator) void {
    allocator.free(self.buffer);
}
