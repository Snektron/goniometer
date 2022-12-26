//! This module deals with the Radeon GPU Profiler file format.

const std = @import("std");
const sqtt = @import("sqtt.zig");
const ThreadTrace = @import("ThreadTrace.zig");

fn fileHeader() sqtt.FileHeader {
    return .{
        .magic = sqtt.magic,
        .ver_major = sqtt.format_major,
        .ver_minor = sqtt.format_minor,
        .flags = .{
            .is_semaphore_queue_timing_etw = true,
            .no_queue_semaphore_timestamps = false,
        },
        .chunk_offset = @sizeOf(sqtt.FileHeader),

        // TODO
        .second = 0,
        .minute = 0,
        .hour = 0,
        .day_in_month = 0,
        .month = 0,
        .year = 0,
        .day_in_week = 0,
        .day_in_year = 0,
        .is_daylight_savings = 0,
    };
}

fn cpuInfo() sqtt.CpuInfo {
    return .{
        .header = .{
            .chunk_id = .{
                .chunk_type = .cpu_info,
                .index = 0,
            },
            .ver_minor = 0,
            .ver_major = 0,
            .size_bytes = @sizeOf(sqtt.CpuInfo),
        },
        .vendor_id = "idk lol     ".*,
        .processor_brand = "a".* ** (12 * 4),
        .cpu_timestamp_freq = std.time.ns_per_s,
        .clock_speed = 0,
        .num_logical_cores = 0,
        .num_physical_cores = 0,
        .system_ram_size = 0,
    };
}

pub fn writeCapture(writer: anytype, trace: *const ThreadTrace) !void {
    _ = trace;

    try writer.writeStruct(fileHeader());
    try writer.writeStruct(cpuInfo());
}

pub fn dumpCapture(name: []const u8, trace: *const ThreadTrace) !void {
    const file = try std.fs.cwd().createFile(name, .{});
    defer file.close();

    var bw = std.io.bufferedWriter(file.writer());
    try writeCapture(bw.writer(), trace);
    try bw.flush();

    std.log.info("saved capture to '{s}'", .{name});
}
