const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    const mode = b.standardReleaseOptions();

    const lib = b.addSharedLibrary("cycle-profiler", "src/main.zig", .unversioned);
    lib.setBuildMode(mode);
    lib.linkLibC();
    lib.addIncludePath("/opt/rocm/include");
    lib.install();
}
