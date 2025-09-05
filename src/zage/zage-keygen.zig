const std = @import("std");
const age = @import("age");
const clap = @import("clap");
const zeit = @import("zeit");

const errors = @import("errors.zig");
const utils = @import("utils.zig");

const Args = struct {};

const Error = errors.Error;

const usage_string =
    \\Usage:
    \\    zage-keygen [-o OUTPUT]
    \\    zage-keygen -y [-o OUTPUT] [INPUT]
    \\
    \\Arguments:
    \\    [INPUT] Path of file containing one or more identities (Default=stdin).
    \\
    \\Options:
    \\    -o, --output OUTPUT         Write the result to the file at path OUTPUT (Default=stdout).
    \\    -y                          Read input identity file and write corresponding recipients to output.
    \\    -v, --version               Print the version information and exit.
    \\    -h, --help                  Print this help message and exit.
    \\
    \\If OUTPUT exists, it will be overwritten.
    \\
;

const param_string =
    \\-o, --output <OUTPUT> Write the result to the file at path OUTPUT (Defualt=stdout).
    \\-y                    Read input identity file and write corresponding recipient to output.
    \\-v, --version         Print the version information and exit.
    \\-h, --help            Print this help message and exit.
    \\<INPUT>               Path of file containing one or more identities (Default=stdin).
    \\
;

const parsers = .{
    .OUTPUT = clap.parsers.string,
    .INPUT = clap.parsers.string,
};

const KeyGenArgs = struct {
    mode: Mode = .keygen,
    output: std.fs.File = std.fs.File.stdout(),
    input: ?std.fs.File = null,

    const Mode = enum {
        keygen,
        convert,
    };
};

pub fn main() !void {
    const gpa = std.heap.page_allocator;

    var args = KeyGenArgs{};
    {
        var args_alloc = std.heap.ArenaAllocator.init(gpa);
        const allocator = args_alloc.allocator();
        defer args_alloc.deinit();

        const params = comptime clap.parseParamsComptime(param_string);

        var diag = clap.Diagnostic{};
        const res = clap.parse(clap.Help, &params, parsers, .{
            .diagnostic = &diag,
            .allocator = allocator,
        }) catch |err| {
            // try diag.reportToFile(.stderr(), err);
            switch (err) {
                Error.InvalidArgument => {
                    try utils.printErrorToStdout("Error: Unknown argument or value\n", .{});
                },
                Error.DoesntTakeValue => {
                    try utils.printErrorToStdout("Error: Flag doesn't take a value\n", .{});
                },
                Error.MissingValue => {
                    try utils.printErrorToStdout("Error: Required value missing\n", .{});
                },
            }
            try utils.printToStdout(usage_string, .{});
            return;
        };

        if (res.args.help != 0) {
            try utils.printToStdout(usage_string, .{});
            return;
        }
        if (res.args.version != 0) {
            try utils.printToStdout("version: beta alpha gamma\n", .{});
            return;
        }

        if (res.args.y != 0) {
            args.mode = .convert;
        }

        if (res.args.output) |path| {
            args.output = std.fs.cwd().createFile(path, .{}) catch {
                try utils.printErrorToStdout("Error: Unable to create output file {s}\n", .{path});
                return;
            };
        }

        if (res.positionals[0]) |input| {
            args.input = std.fs.cwd().openFile(input, .{}) catch {
                try utils.printErrorToStdout("Error: Unable to open input file {s}\n", .{input});
                return;
            };
        }
    }

    switch (args.mode) {
        .keygen => {
            var id: age.X25519Identity = try .generate();

            // TODO: optimize the size of the buffer
            var buffer: [1024]u8 = undefined;
            var writer = args.output.writer(&buffer);

            // TODO: condition on if we're not already printing to stdout or
            // stderr with our output file.
            try utils.printToStderr("Public key: {s}\n", .{id.recipient().toBech32String()});

            const now = try zeit.instant(.{});
            var time_buf: [100]u8 = undefined;
            // TODO: implement our own version of bufPrint so we can write directly into the output writer?
            try writer.interface.print("# created: {s}\n", .{try now.time().bufPrint(&time_buf, .rfc3339)});

            try writer.interface.print("# public key: {s}\n", .{id.recipient().toBech32String()});
            try writer.interface.print("{s}\n", .{id.toBech32String()});

            try writer.interface.flush();
        },
        .convert => {
            // TODO: create age.Identity.parse function const ids = try
            // age.Identity.parse(args.input)
        },
    }
}
