const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib = b.addSharedLibrary(.{
        .name = "goniometer",
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });
    lib.linkLibC();
    lib.addIncludePath(.{ .path = "/opt/rocm/include" });
    b.installArtifact(lib);

    const rgp_dump = b.addExecutable(.{
        .name = "rgp-dump",
        .root_source_file = .{ .path = "src/rgp_dump.zig" },
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(rgp_dump);

    const rgp_cut = b.addExecutable(.{
        .name = "rgp-cut",
        .root_source_file = .{ .path = "src/rgp_cut.zig" },
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(rgp_cut);
}
