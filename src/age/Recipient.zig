const Stanza = @import("Stanza.zig");
const AgeError = @import("errors.zig").AgeError;
const mem = @import("std").mem;

pub const Recipient = @This();

ptr: *anyopaque,
wrap: *const fn (*anyopaque, mem.Allocator, []const u8) AgeError![]Stanza,

/// This function is not intended to be called except from within the implementation of a Recipient.
inline fn rawWrap(self: Recipient, allocator: mem.Allocator, file_key: []const u8) AgeError![]Stanza {
    return self.wrap(self.ptr, allocator, file_key);
}

/// Call Stanza.deinit for each stanza in []Stanza
pub fn wrapFileKey(self: Recipient, allocator: mem.Allocator, file_key: []const u8) AgeError![]Stanza {
    return self.rawWrap(allocator, file_key);
}
