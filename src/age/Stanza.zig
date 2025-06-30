const constants = @import("constants.zig");
const Stanza = @This();

tag: []const u8,
args: [constants.MAX_ARGS][]const u8,
body: [constants.FILE_KEY_BYTES + constants.ChaCha20Poly1305.tag_length]u8,
buf: []align(32) u8,
