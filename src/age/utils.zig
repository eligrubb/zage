const std = @import("std");

// TODO: optimize this size
const print_buffer_size: usize = 1024;

pub fn trimWhitespace(line: []const u8) []const u8 {
    // trim whitespace from beginning
    var start: usize = 0;
    var end: usize = line.len;
    while (start < end and std.ascii.isWhitespace(line[start])) start += 1;
    // aaaaand trim whitespace from end
    while (end > 0 and std.ascii.isWhitespace(line[end - 1])) end -= 1;
    return line[start..end];
}

// pub fn printToStderr(comptime fmt: []const u8, args: anytype) !void {
//     var stderr_buffer: [print_buffer_size]u8 = undefined;
//     var stderr_writer = std.fs.File.stderr().writer(&stderr_buffer);
//     const stderr = &stderr_writer.interface;
//     try stderr.print(fmt, args);
//     try stderr.flush();
// }
