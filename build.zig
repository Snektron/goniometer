const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    const mode = b.standardReleaseOptions();

    const lib = b.addSharedLibrary("cycle-profiler", "src/main.zig", .unversioned);
    lib.setBuildMode(mode);
    lib.linkLibC();
    lib.addIncludePath("/opt/rocm/include");
    lib.install();

    const rgp_dump = b.addExecutable("rgp-dump", "src/rgp_dump.zig");
    rgp_dump.setBuildMode(mode);
    rgp_dump.install();

    const rgp_cut = b.addExecutable("rgp-cut", "src/rgp_cut.zig");
    rgp_cut.setBuildMode(mode);
    rgp_cut.install();
}
