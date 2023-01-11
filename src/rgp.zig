//! This module deals with the Radeon GPU Profiler file format.

const std = @import("std");
const sqtt = @import("sqtt.zig");
const hsa = @import("hsa.zig");
const ThreadTrace = @import("ThreadTrace.zig");
const AgentInfo = @import("Profiler.zig").AgentInfo;

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

        // TODO: fix these bogus values
        .second = 57,
        .minute = 17,
        .hour = 17,
        .day_in_month = 18,
        .month = 2,
        .year = 121,
        .day_in_week = 4,
        .day_in_year = 76,
        .is_daylight_savings = 1,
    };
}

fn chunkHeader(chunk_type: sqtt.ChunkHeader.Type, size: u32, ver_major: u16, ver_minor: u16) sqtt.ChunkHeader {
    return .{
        .chunk_id = .{
            .chunk_type = chunk_type,
            .index = 0,
        },
        .ver_minor = ver_minor,
        .ver_major = ver_major,
        .size_bytes = size,
    };
}

fn cpuInfo(agent: AgentInfo) sqtt.CpuInfo {
    const props = agent.properties;
    // Note: mesa reports the name from /proc/cpuinfo, while this will return something like 'CPU'.
    // TODO: Fill in the remaining attributes.
    return .{
        .header = chunkHeader(.cpu_info, @sizeOf(sqtt.CpuInfo), 0, 0),
        .vendor_id = props.vendor_name[0..12].*,
        .processor_brand = props.product_name[0..48].*,
        .cpu_timestamp_freq = props.timestamp_freq,
        .clock_speed = props.clock_freq,
        .num_logical_cores = 0,
        .num_physical_cores = 0,
        .system_ram_size = 0,
    };
}

fn asicInfo(agent: AgentInfo) sqtt.AsicInfo {
    const props = agent.properties;
    const gpu_props = props.gpu_properties.?;
    // The assignment of these fields is mostly either based on mesa, just a random guess,
    // or hardcoded for GFX1030 (v620).
    // TODO is to revise this function and add the required fields.
    const clock_freq = @as(u64, props.clock_freq) * 1000_000;
    const mem_freq = @as(u64, gpu_props.memory_freq) * 1000_000;
    return sqtt.AsicInfo{
        .header = chunkHeader(.asic_info, @sizeOf(sqtt.AsicInfo), 0, 4),
        .flags = .{
            .sc_packer_numbering = false,
            .ps1_event_tokens_enabled = true,
        },
        .trace_shader_core_clock = clock_freq,
        .trace_memory_clock = mem_freq,
        .device_id = props.chip_id,
        .device_revision_id = props.asic_revision,
        .vgprs_per_simd = 512 * 2,
        .sgprs_per_simd = 16 * 128,
        .shader_engines = props.shader_engines,
        .compute_units_per_shader_engine = props.compute_units / props.shader_engines,
        .simds_per_compute_unit = props.simds_per_cu,
        .wavefronts_per_simd = 20, // Note: .max_waves_per_cu / simds_per_cu is incorrect here.
        .minimum_vgpr_alloc = 4,
        .vgpr_alloc_granularity = 8,
        .minimum_sgpr_alloc = 128,
        .sgpr_alloc_granularity = 128,
        .hardware_contexts = 8,
        .gpu_type = .discrete,
        .gfxip_level = switch (gpu_props.gcn_arch.major()) {
            0x6 => .gfxip_6,
            0x7 => .gfxip_7,
            0x8 => switch (gpu_props.gcn_arch.minor()) {
                0 => .gfxip_8,
                1 => .gfxip_8_1,
                else => .none,
            },
            0x9 => .gfxip_9,
            0x10 => switch (gpu_props.gcn_arch.minor()) {
                1 => .gfxip_10_1,
                3 => .gfxip_10_3,
                else => blk: {
                    break :blk .none;
                },
            },
            0x11 => .gfxip_11,
            else => .none,
        },
        .gpu_index = 0, // TODO: we can probably find this out.
        .gds_size = 0,
        .gds_per_shader_engine = 0,
        .ce_ram_size = 0,
        .ce_ram_size_graphics = 32768,
        .ce_ram_size_compute = 0,
        .max_number_of_dedicated_cus = 0,
        .vram_size = 32 * 1024 * 1024 * 1024,
        .vram_bus_width = gpu_props.memory_width,
        .l2_cache_size = props.cache_size[1],
        .l1_cache_size = props.cache_size[0],
        .lds_size = 64 * 1024,
        .gpu_name = props.name ++ [_]u8{0} ** 192,
        .alu_per_clock = 0,
        .texture_per_clock = 0,
        .prims_per_clock = @intToFloat(f32, props.shader_engines) * 2,
        .pixels_per_clock = 0,
        .gpu_timestamp_frequency = props.timestamp_freq,
        .max_shader_core_clock = clock_freq,
        .max_memory_clock = mem_freq,
        .memory_ops_per_clock = 16,
        .memory_chip_type = .gddr6,
        .lds_granularity = 64 * 4,
        .cu_mask = .{ .{ 1023, 1023 }, .{ 1023, 1023 } } ++ .{.{0} ** 2} ** 30,
    };
}

fn apiInfo() sqtt.ApiInfo {
    return .{
        .header = chunkHeader(.api_info, @sizeOf(sqtt.ApiInfo), 0, 1),
        .api_type = .hip,
        .major_version = 0,
        .minor_version = 0,
        .profiling_mode = .present,
        .profiling_mode_data = undefined, // TODO: zero
        .instruction_trace_mode = .disabled,
        .instruction_trace_data = undefined, // TODO: zero
    };
}

/// Models a full RGP trace.
pub const Capture = struct {
    pub const LoadEvent = struct {
        event_type: sqtt.ObjectLoaderEvents.EventType,
        base_address: u64,
        code_object_hash: u64,
        timestamp: u64,
    };

    pub const CodeObject = struct {
        elf_binary: []const u8,
    };

    cpu_agent: *const AgentInfo,
    gpu_agent: *const AgentInfo,
    traces: []const ThreadTrace.Trace,
    load_events: []const LoadEvent,
    code_objects: []const CodeObject,

    pub fn write(self: Capture, backing_writer: anytype) !void {
        var cw = std.io.countingWriter(backing_writer);
        const writer = cw.writer();

        try writer.writeStruct(fileHeader());
        try writer.writeStruct(cpuInfo(self.cpu_agent.*));
        try writer.writeStruct(asicInfo(self.gpu_agent.*));
        try writer.writeStruct(apiInfo());

        {
            const code_objects = self.code_objects[0..1];
            const co_alignment = 4; // Apparently code objects must be aligned by 4 bytes.
            var size: usize = @sizeOf(sqtt.CodeObjectDatabase);
            for (code_objects) |co| {
                const aligned_size = std.mem.alignForward(co.elf_binary.len, co_alignment);
                size += @sizeOf(sqtt.CodeObjectDatabase.Record) + aligned_size;
            }
            try writer.writeStruct(sqtt.CodeObjectDatabase{
                .header = chunkHeader(.code_object_database, @intCast(u32, size), 0, 0),
                .offset = @intCast(u32, cw.bytes_written),
                .flags = 0,
                .size = @intCast(u32, size),
                .record_count = @intCast(u32, code_objects.len),
            });

            for (code_objects) |co| {
                const aligned_size = std.mem.alignForward(co.elf_binary.len, co_alignment);
                try writer.writeStruct(sqtt.CodeObjectDatabase.Record{
                    .record_size = @intCast(u32, aligned_size),
                });
                try writer.writeAll(co.elf_binary);
                // Add the misaligned bytes.
                try writer.writeByteNTimes(0, aligned_size - co.elf_binary.len);
            }
        }

        {
            const size = @sizeOf(sqtt.ObjectLoaderEvents) + @sizeOf(sqtt.ObjectLoaderEvents.Record) * self.load_events.len;
            try writer.writeStruct(sqtt.ObjectLoaderEvents{
                .header = chunkHeader(.code_object_loader_events, @intCast(u32, size), 1, 1),
                .offset = @intCast(u32, cw.bytes_written),
                .flags = 0,
                .record_size = @sizeOf(sqtt.ObjectLoaderEvents.Record),
                .record_count = @intCast(u32, self.load_events.len),
            });

            for (self.load_events) |event| {
                try writer.writeStruct(sqtt.ObjectLoaderEvents.Record{
                    .event_type = event.event_type,
                    .base_address = event.base_address,
                    .code_object_hash = .{ event.code_object_hash, event.code_object_hash },
                    .timestamp = event.timestamp,
                });
            }
        }

        // Just infer the PSO correlation from the load events for now.
        {
            const size = @sizeOf(sqtt.PsoCorrelation) + @sizeOf(sqtt.PsoCorrelation.Record) * self.load_events.len;
            try writer.writeStruct(sqtt.PsoCorrelation{
                .header = chunkHeader(.pso_correlation, @intCast(u32, size), 0, 0),
                .offset = @intCast(u32, cw.bytes_written),
                .flags = 0,
                .record_size = @sizeOf(sqtt.PsoCorrelation.Record),
                .record_count = @intCast(u32, self.load_events.len),
            });

            for (self.load_events) |event| {
                try writer.writeStruct(sqtt.PsoCorrelation.Record{
                    .api_pso_hash = event.code_object_hash,
                    .internal_pipeline_hash = .{ event.code_object_hash, event.code_object_hash },
                    .api_object_name = "a".* ** 64,
                });
            }
        }

        for (self.traces) |trace, i| {
            try writer.writeStruct(sqtt.SqttDesc{
                .header = .{
                    .chunk_id = .{
                        .chunk_type = .sqtt_desc,
                        .index = @intCast(u8, i),
                    },
                    .ver_minor = 2,
                    .ver_major = 0,
                    .size_bytes = @sizeOf(sqtt.SqttDesc),
                },

                .shader_engine_index = trace.shader_engine,
                .version = .@"2.4",
                .instrumentation_spec_version = 1,
                .instrumentation_api_version = 0,
                .compute_unit_index = trace.compute_unit,
            });

            try writer.writeStruct(sqtt.SqttData{
                .header = .{
                    .chunk_id = .{
                        .chunk_type = .sqtt_data,
                        .index = @intCast(u8, i),
                    },
                    .ver_minor = 0,
                    .ver_major = 0,
                    .size_bytes = @intCast(u32, @sizeOf(sqtt.SqttData) + trace.data.len),
                },
                .offset = @intCast(i32, @sizeOf(sqtt.SqttData) + cw.bytes_written),
                .size = @intCast(u32, trace.data.len),
            });

            try writer.writeAll(trace.data);
        }
    }

    pub fn dump(self: Capture, name: []const u8) !void {
        const file = try std.fs.cwd().createFile(name, .{});
        defer file.close();

        var bw = std.io.bufferedWriter(file.writer());
        try self.write(bw.writer());
        try bw.flush();
    }
};
