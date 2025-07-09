const std = @import("std");
const constants = @import("constants.zig");
const mem = std.mem;

pub const Stanza = @This();

tag: []const u8, // pointer to global array, 8 bytes
args: [constants.MAX_ARGS]?[]const u8, // one or two args, slices, pointers to strings, 8 bytes?
//buffer: []align(16) u8, // pointer to heap array, 8 bytes
arena: ?std.heap.ArenaAllocator,
body: [constants.BASE64_ENCODED_FILE_KEY_BYTES]u8, // 48 bytes

pub fn deinit(self: Stanza) void {
    var arena = self.arena orelse return;
    arena.deinit();
}
