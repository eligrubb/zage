const std = @import("std");

// TODO: optimize this size
const print_buffer_size: usize = 1024;

pub fn printToStdout(comptime fmt: []const u8, args: anytype) !void {
    var stdout_buffer: [print_buffer_size]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;
    try stdout.print(fmt, args);
    try stdout.flush();
}

pub fn printToStderr(comptime fmt: []const u8, args: anytype) !void {
    var stderr_buffer: [print_buffer_size]u8 = undefined;
    var stderr_writer = std.fs.File.stderr().writer(&stderr_buffer);
    const stderr = &stderr_writer.interface;
    try stderr.print(fmt, args);
    try stderr.flush();
}

pub fn printErrorToStdout(comptime fmt: []const u8, args: anytype) !void {
    try printToStderr(fmt, args);
    const error_message =
        \\
        \\Report unexpected or unhelpful errors at https://eligrubb.com/zage/report
        \\
    ;
    try printToStderr(error_message, .{});
}
