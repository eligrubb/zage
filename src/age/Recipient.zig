const Stanza = @import("Stanza.zig");
const AgeError = @import("errors.zig").AgeError;
const std = @import("std");
const mem = std.mem;
const Io = std.Io;
const utils = @import("utils.zig");

const Recipient = @This();

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

const X25519Recipient = @import("x25519.zig").X25519Recipient;
const SshRecipient = @import("ssh.zig").SshRecipient;

pub fn parse(string: []const u8) AgeError!Recipient {
    // TODO(eli): handle plugin case?
    return X25519Recipient.initFromBech32String(string) orelse
        SshRecipient.initFromString(string) orelse
        AgeError.UnknownRecipient;
}

pub fn parseFile(allocator: mem.Allocator, source: *Io.Reader) AgeError![]Recipient {
    // TODO(eli): see if we can figure out an initial capacity based on our reader...
    var recipients: std.ArrayList(Recipient) = .initCapacity(allocator, 1);
    errdefer recipients.deinit(allocator);

    while (source.takeDelimiterExclusive('\n')) |line| {
        const trimmed = utils.trimWhitespace(line);

        // ignore empty or comment lines
        if (trimmed.len != 0 and trimmed[0] != '#')
            try recipients.append(allocator, try parse(trimmed));
    } else |err| switch (err) {
        error.EndOfStream => {
            // still need to process the last line this just means it ended
            // on something other than a line break
        },
        error.StreamTooLong => {
            // line couldn't fit in buffer, in theory we can just assume
            // hitting this error is a malformed identity line, but that
            // assumes proper size for our parser_buffer
            // for now... print to stderr and continue looping?
            // try utils.printToStderr("Error: Line too long for buffer\n", .{});
            return AgeError.ReaderBufferTooSmall;
        },
        else => |e| return e,
    }

    return recipients.toOwnedSlice(allocator);
}
