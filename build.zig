const std = @import("std");

const minimum_build_zig_version = "0.15.1";
const version = std.SemanticVersion{ .major = 0, .minor = 1, .patch = 0 };

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const age_mod = b.addModule("age", .{ .root_source_file = b.path("src/age.zig") });

    const bech32_mod = b.addModule("bech32", .{ .root_source_file = b.path("src/age/internal/bech32.zig") });
    age_mod.addImport("bech32", bech32_mod);

    const zecrecy_mod = b.dependency("zecrecy", .{
        .target = target,
    });
    age_mod.addImport("zecrecy", zecrecy_mod.module("zecrecy"));

    // const bech32 = b.dependency("bech32", .{});
    // mod.addImport("bech32", bech32.module("bech32"));

    const tests_step = b.step("test", "Run tests");

    const zage_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/zage.zig"),
            .target = target,
        }),
    });

    const age_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/age.zig"),
            .target = target,
            .imports = &.{
                .{ .name = "zecrecy", .module = zecrecy_mod.module("zecrecy") },
            },
        }),
    });

    const exe = b.addExecutable(.{
        .name = "zage",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/zage.zig"),
            .imports = &.{
                .{ .name = "age", .module = age_mod },
            },
            .target = target,
            .optimize = optimize,
        }),
    });

    zage_tests.root_module.addImport("age", age_mod);
    age_tests.root_module.addImport("zecrecy", zecrecy_mod.module("zecrecy"));

    const zage_tests_run = b.addRunArtifact(zage_tests);
    const age_tests_run = b.addRunArtifact(age_tests);
    tests_step.dependOn(&zage_tests_run.step);
    tests_step.dependOn(&age_tests_run.step);
    b.getInstallStep().dependOn(tests_step);

    exe.root_module.addImport("age", age_mod);

    b.installArtifact(exe);
}
