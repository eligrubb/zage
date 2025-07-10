const std = @import("std");
const mem = std.mem;

pub const Stanza = @This();
/// base64 encoded file key length
pub const body_length = 43;
pub const max_args = 2;

tag: []const u8, // pointer to global array, 8 bytes
args: [max_args]?[]const u8, // one or two args, slices, pointers to strings, 8 bytes?
//buffer: []align(16) u8, // pointer to heap array, 8 bytes
arena: ?std.heap.ArenaAllocator,
body: [body_length]u8, // 48 bytes

pub fn deinit(self: Stanza) void {
    var arena = self.arena orelse return;
    arena.deinit();
}
