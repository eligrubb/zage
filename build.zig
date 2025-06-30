const std = @import("std");

const minimum_build_zig_version = "0.15.0-dev.847+850655f06";
// Define single semantic version for your library, examples, etc.
const version = std.SemanticVersion{ .major = 0, .minor = 1, .patch = 0 };

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.addModule("age", .{ .root_source_file = b.path("src/age.zig") });

    const tests_step = b.step("test", "Run tests");

    const tests = b.addTest(.{
        .version = version,
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/zage.zig"),
            .target = target,
        }),
    });

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

    tests.root_module.addImport("age", mod);

    const tests_run = b.addRunArtifact(tests);
    tests_step.dependOn(&tests_run.step);
    b.getInstallStep().dependOn(tests_step);

    exe.root_module.addImport("age", mod);

    b.installArtifact(exe);
}
