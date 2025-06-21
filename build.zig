const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.addModule("age", .{ .root_source_file = b.path("src/age.zig") });

    const exe = b.addExecutable(.{
        .name = "zage",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/zage.zig"),
            .imports = &.{
                .{ .name = "age", .module = mod },
            },
            .target = target,
            .optimize = optimize,
        }),
    });

    b.installArtifact(exe);
}
