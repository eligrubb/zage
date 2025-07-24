const Stanza = @import("Stanza.zig");
const AgeError = @import("errors.zig").AgeError;
const mem = @import("std").mem;

pub const Identity = @This();
pub const file_key_length: usize = 16;

ptr: *anyopaque,
unwrap: *const fn (*anyopaque, mem.Allocator, []const Stanza) AgeError![file_key_length]u8,

inline fn rawUnwrap(self: Identity, allocator: mem.Allocator, stanzas: []const Stanza) AgeError![file_key_length]u8 {
    return self.unwrap(self.ptr, allocator, stanzas);
}

pub fn unwrapFileKey(self: Identity, allocator: mem.Allocator, stanzas: []const Stanza) AgeError![file_key_length]u8 {
    return self.rawUnwrap(allocator, stanzas);
}
