const std = @import("std");

pub fn build(b: *std.Build) void {
    const step = b.step("build", "Run npm build script");

    const run_cmd = b.addSystemCommand(&[_][]const u8{
        "npm", "run", "build",
    });

    step.dependOn(&run_cmd.step);
    b.default_step.dependOn(step);
}
