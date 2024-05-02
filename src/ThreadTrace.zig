//! This module contains stuff that deals with gathering the actual thread trace.
const Self = @This();

const std = @import("std");
const Allocator = std.mem.Allocator;

const pm4 = @import("pm4.zig");
const hsa = @import("hsa.zig");
const sqtt = @import("sqtt.zig");
const CmdBuf = @import("CmdBuf.zig");
const AgentInfo = @import("Profiler.zig").AgentInfo;

/// The default size of the thread trace buffer, values taken from rocprof/mesa.
const thread_trace_buffer_size = 32 * 1024 * 1024;

/// The default size for the start, stop and update command buffers. Increase as needed, but should be aligned
/// to page size (0x1000) in bytes. Note: size is in words.
const start_cmd_size = 0x4000;
const stop_cmd_size = 0x4000;
const update_cmd_max_size = 0x4000;

const sqtt_buffer_align_shift = 12;
const sqtt_buffer_align = 1 << sqtt_buffer_align_shift;

/// Additional thread trace information that is obtained from the gpu.
/// Structure taken from Mesa.
pub const ThreadTraceInfo = extern struct {
    cur_offset: u32,
    trace_status: u32,
    arch: extern union {
        gfx9_write_counter: u32,
        gfx10_dropped_cntr: u32,
    },
};

/// Represents a finished trace, for a single shader engine.
pub const Trace = struct {
    info: ThreadTraceInfo,
    /// The sqtt data, as reported by the gpu.
    /// Memory is owned by the allocator passed to read().
    data: []const u8,
    /// The shader engine that this trace was recorded for.
    shader_engine: u32,
    /// The compute unit on the shader engine that this trace was recorded for.
    compute_unit: u32,

    pub fn deinit(self: *Trace, a: Allocator) void {
        a.free(self.data);
        self.* = undefined;
    }
};

/// The start packets. They are here to avoid having to reconstruct them.
start_packet: hsa.Pm4IndirectBufferPacket,
/// The stop packet. Note: has a signal that should be used to wait on this packet.
stop_packet: hsa.Pm4IndirectBufferPacket,
/// The thread trace token update packet. Note: has a signal that should be used to wait on this packet,
/// so that contents are not overwritten while its still being used.
update_packet: hsa.Pm4IndirectBufferPacket,
/// Backing command buffers for the above packets.
/// TODO: Give Pm4IndirectBufferPacket a buffer() function so that we dont need to duplicate it?
start_commands: []pm4.Word,
stop_commands: []pm4.Word,
update_commands: []pm4.Word,
/// The buffer to which the final SQTT thread trace will be written to, from the GPU.
output_buffer: []u8,
/// Command number counter
cmd_id: u32,

pub fn init(
    instance: *const hsa.Instance,
    cpu_pool: hsa.MemoryPool,
    agent_info: AgentInfo,
) !Self {
    // TODO: Consolidate allocations.

    const output_buffer = try instance.memoryPoolAllocate(
        u8,
        cpu_pool,
        threadTraceBufferSize(agent_info.properties.shader_engines, thread_trace_buffer_size),
    );
    @memset(output_buffer, 0);
    errdefer instance.memoryPoolFree(output_buffer);
    instance.agentsAllowAccess(output_buffer.ptr, &.{agent_info.agent});

    const start_commands = try startCommands(instance, cpu_pool, agent_info.properties.shader_engines, output_buffer);
    errdefer instance.memoryPoolFree(start_commands);
    instance.agentsAllowAccess(start_commands.ptr, &.{agent_info.agent});

    const stop_commands = try stopCommands(instance, cpu_pool, agent_info.properties.shader_engines, output_buffer);
    errdefer instance.memoryPoolFree(stop_commands);
    instance.agentsAllowAccess(stop_commands.ptr, &.{agent_info.agent});

    const update_commands = try instance.memoryPoolAllocate(pm4.Word, cpu_pool, update_cmd_max_size);
    errdefer instance.memoryPoolFree(update_commands);
    instance.agentsAllowAccess(update_commands.ptr, &.{agent_info.agent});

    const completion_signal = try instance.createSignal(1, &.{});
    errdefer instance.destroySignal(completion_signal);

    return Self{
        .start_packet = hsa.Pm4IndirectBufferPacket.init(start_commands, null),
        .stop_packet = hsa.Pm4IndirectBufferPacket.init(stop_commands, completion_signal),
        .update_packet = undefined, // Set in update().
        .output_buffer = output_buffer,
        .start_commands = start_commands,
        .stop_commands = stop_commands,
        .update_commands = update_commands,
        .cmd_id = 0,
    };
}

pub fn deinit(self: *Self, instance: *const hsa.Instance) void {
    instance.memoryPoolFree(self.output_buffer.ptr);
    instance.memoryPoolFree(self.start_commands.ptr);
    instance.memoryPoolFree(self.stop_commands.ptr);
    instance.memoryPoolFree(self.update_commands.ptr);
    instance.destroySignal(self.stop_packet.completion_signal);
    self.* = undefined;
}

/// Update the SQTT token. This should be invoked before a new kernel is launched to update its state.
/// The resulting packet should be submitted, and the corresponding signal should be waited on and
/// reset before calling this function again.
pub fn update(
    self: *Self,
    kernel_name: []const u8,
    code_object_hash: u64,
    wgp_count_x: u32,
    wgp_count_y: u32,
    wgp_count_z: u32,
) *const hsa.Pm4IndirectBufferPacket {
    var cmdbuf = CmdBuf{
        .cap = @intCast(self.update_commands.len),
        .buf = self.update_commands.ptr,
    };

    cmdbuf.sqttMarker(sqtt.marker.PipelineBind, &.{
        .extra_dwords = 0,
        .bind_point = .compute,
        .cmdbuf_id = 0, // TODO?
        .api_pso_hash = code_object_hash,
    });

    var name_marker = sqtt.marker.UserEventWithString{
        .user_event = .{
            .extra_dwords = 0,
            .data_type = .object_name,
        },
        .str_len = @intCast(kernel_name.len),
        .str_data = .{0} ** 4096,
    };
    // TODO: Check size and bound.
    @memcpy(name_marker.str_data[0..kernel_name.len], kernel_name);
    const words: [*]const pm4.Word = @ptrCast(&name_marker);
    cmdbuf.sqttDataMarker(words[0 .. @sizeOf(sqtt.marker.UserEvent) / @sizeOf(pm4.Word) + 1 + (std.math.divCeil(u32, @intCast(kernel_name.len), 4) catch unreachable)]);

    cmdbuf.sqttMarker(sqtt.marker.EventWithDims, &.{
        .event = .{
            .extra_dwords = 0,
            .api_type = .cmd_nd_range_kernel,
            .cmd_id = self.cmd_id,
            .cmdbuf_id = 0, // TODO?
            .has_thread_dims = true,
        },
        .wgp_count_x = wgp_count_x,
        .wgp_count_y = wgp_count_y,
        .wgp_count_z = wgp_count_z,
    });
    self.cmd_id +%= 1;

    self.update_packet = hsa.Pm4IndirectBufferPacket.init(cmdbuf.words(), null);
    return &self.update_packet;
}

fn threadTraceBufferSize(shader_engines: u32, per_trace_buffer_size: u32) u32 {
    const aligned_buffer_size = std.mem.alignForward(usize, per_trace_buffer_size, sqtt_buffer_align);
    const size = std.mem.alignForward(usize, @sizeOf(ThreadTraceInfo) * shader_engines, sqtt_buffer_align) +
        aligned_buffer_size * shader_engines;
    return @intCast(size);
}

fn threadTraceInfoOffset(shader_engine: u32) usize {
    return @sizeOf(ThreadTraceInfo) * shader_engine;
}

fn threadTraceDataOffset(per_trace_buffer_size: u32, shader_engine: u32, shader_engines: u32) usize {
    var data_offset = std.mem.alignForward(usize, @sizeOf(ThreadTraceInfo) * shader_engines, sqtt_buffer_align);
    data_offset += std.mem.alignForward(usize, per_trace_buffer_size, sqtt_buffer_align) * shader_engine;
    return data_offset;
}

fn startCommands(
    instance: *const hsa.Instance,
    cpu_pool: hsa.MemoryPool,
    shader_engines: u32,
    output_buffer: []u8,
) ![]pm4.Word {
    // Magic values and stuff in this function are all taken from
    // radv_emit_thread_trace_start.

    var cmdbuf = try CmdBuf.alloc(instance, cpu_pool, start_cmd_size);
    errdefer cmdbuf.free(instance);

    const shifted_size = @shrExact(thread_trace_buffer_size, sqtt_buffer_align_shift);
    const output_va = @intFromPtr(output_buffer.ptr);

    // wait until the queue is idle
    cmdbuf.cacheFlush(.{
        .icache = true,
        .scache = true,
        .vcache = true,
        .l2 = true,
        .cs_partial_flush = true,
    });

    cmdbuf.setUConfigReg(.rlc_perfmon_clock_cntl, .{
        .inhibit_clock = true,
    });

    cmdbuf.setUConfigReg(.spi_config_cntl, .{
        .gpr_write_priority = 0x2c688,
        .exp_priority_order = 3,
        .enable_sqg_top_events = true,
        .enable_sqg_bop_events = true,
        .rsrc_mgmt_reset = false,
        .ttrace_stall_all = false,
        .alloc_arb_lru_ena = false,
        .exp_arb_lru_ena = false,
        .ps_pkr_priority_cntl = 3,
    });

    // reset counters
    cmdbuf.setUConfigReg(.cp_perfmon_cntl, .{
        .perfmon_state = .disable_and_reset,
        .spm_perfmon_state = .disable_and_reset,
        .enable_mode = .always_count,
        .sample_enable = false,
    });

    // TODO: mesa only enables thread trace for shader engines/compute units which are enabled.
    // We may be able to query that information with hsa_amd_queue_cu_get_mask, but its not
    // terribly clear on documentation so just skip that for now.
    // Assume that all shader engines are enabled, and that the first active CU is 0.

    var shader_engine: u32 = 0;
    while (shader_engine < shader_engines) : (shader_engine += 1) {
        // Note: this assumes that the device and host VA are the same.
        // TODO: Is it? We can find out with hsa_amd_pointer_info.
        const data_va = output_va + threadTraceDataOffset(thread_trace_buffer_size, shader_engine, shader_engines);
        const shifted_va = @shrExact(data_va, sqtt_buffer_align_shift);
        const first_active_cu = 0;

        cmdbuf.setUConfigReg(.grbm_gfx_index, .{
            .instance_index = 0,
            .sa_index = 0,
            .se_index = @intCast(shader_engine),
            .sa_broadcast_writes = false,
            .instance_broadcast_writes = true,
            .se_broadcast_writes = false,
        });

        // Assume gfx1030
        // Note: order is apparently important for the following 2 registers.
        cmdbuf.setPrivilegedConfigReg(.sqtt_buf0_size, .{
            .size = @intCast(shifted_size),
            .base_hi = @intCast(shifted_va >> 32),
        });
        cmdbuf.setPrivilegedConfigReg(.sqtt_buf0_base, @truncate(shifted_va));

        cmdbuf.setPrivilegedConfigReg(.sqtt_mask, .{
            .wtype_include = 0x7F,
            .sa_sel = 0,
            .wgp_sel = @intCast(first_active_cu / 2),
            .simd_sel = 0,
        });

        cmdbuf.setPrivilegedConfigReg(.sqtt_token_mask, .{
            .token_exclude = .{
                .perf = true,
            },
            .bop_events_token_include = true,
            .reg_include = .{
                .sqdec = true,
                .shdec = true,
                .gfxudec = true,
                .comp = true,
                .context = true,
                .config = true,
            },
            .inst_exclude = 0,
            .reg_exclude = 0,
            .reg_detail_all = false,
        });

        cmdbuf.setPrivilegedConfigReg(.sqtt_ctrl, .{
            .mode = 1,
            .util_timer = true,
            .hiwater = 5,
            .rt_freq = 2,
            .draw_event_en = true,
            .reg_stall_en = true,
            .spi_stall_en = true,
            .sq_stall_en = true,
            .reg_drop_on_stall = false,
            .lowater_offset = 4, // Note: gfx10 specific
            .auto_flush_mode = true, // Required for a gfx10 specific bug
        });
    }

    // Note: In mesa this mentions restoring stuff. Should we read the previous register state
    // and set it back to whatever it was?
    cmdbuf.setUConfigReg(.grbm_gfx_index, .{
        .instance_index = 0,
        .sa_index = 0,
        .se_index = 0,
        .sa_broadcast_writes = true,
        .instance_broadcast_writes = true,
        .se_broadcast_writes = true,
    });

    // HSA queue should be compute, right? Right??
    cmdbuf.setShReg(.compute_thread_trace_enable, .{
        .enable = true,
    });

    return cmdbuf.words();
}

fn stopCommands(
    instance: *const hsa.Instance,
    cpu_pool: hsa.MemoryPool,
    shader_engines: u32,
    output_buffer: []u8,
) ![]pm4.Word {
    var cmdbuf = try CmdBuf.alloc(instance, cpu_pool, stop_cmd_size);
    errdefer cmdbuf.free(instance);

    // Wait-for-idle before ending thread trace.
    cmdbuf.cacheFlush(.{
        .icache = true,
        .scache = true,
        .vcache = true,
        .l2 = true,
        .cs_partial_flush = true,
    });

    cmdbuf.setShReg(.compute_thread_trace_enable, .{
        .enable = false,
    });

    cmdbuf.writeEventNonSample(.thread_trace_finish, 0);

    var shader_engine: u32 = 0;
    while (shader_engine < shader_engines) : (shader_engine += 1) {
        cmdbuf.setUConfigReg(.grbm_gfx_index, .{
            .instance_index = 0,
            .sa_index = 0,
            .se_index = @intCast(shader_engine),
            .sa_broadcast_writes = false,
            .instance_broadcast_writes = true,
            .se_broadcast_writes = false,
        });

        const sqtt_status = pm4.PrivilegedRegister.sqtt_status;

        cmdbuf.waitRegMem(.{
            .function = .ne,
            .mem_space = .register,
            .engine = .me,
            .poll_addr = sqtt_status.address(),
            .reference = 0,
            .mask = @bitCast(sqtt_status.Type(){
                .finish_done = std.math.maxInt(u12),
            }),
            .poll_interval = 4,
        });

        // Stop tracing
        cmdbuf.setPrivilegedConfigReg(.sqtt_ctrl, .{
            .mode = 0,
            .util_timer = true,
            .hiwater = 5,
            .rt_freq = 2,
            .draw_event_en = true,
            .reg_stall_en = true,
            .spi_stall_en = true,
            .sq_stall_en = true,
            .reg_drop_on_stall = false,
            .lowater_offset = 4, // Note: gfx10 specific
            .auto_flush_mode = true, // Required for a gfx10 specific bug
        });

        // And wait for the trace to be completely finished.
        cmdbuf.waitRegMem(.{
            .function = .eq,
            .mem_space = .register,
            .engine = .me,
            .poll_addr = sqtt_status.address(),
            .reference = 0,
            .mask = @bitCast(sqtt_status.Type(){
                .busy = true,
            }),
            .poll_interval = 4,
        });

        // Copy back the info structure.
        const info_regs = [_]pm4.PrivilegedRegister{
            .sqtt_wptr,
            .sqtt_status,
            .sqtt_dropped_cntr,
        };

        // Assumes again that the gpu and cpu pointers match.
        const va = @intFromPtr(output_buffer.ptr);
        const info_va = va + threadTraceInfoOffset(shader_engine);

        for (info_regs, 0..) |reg, i| {
            cmdbuf.copyData(.{
                .control = .{
                    .src_sel = .perf,
                    .dst_sel = .tc_l2,
                    .count_sel = 0,
                    .wr_confirm = true,
                    .engine_sel = 0,
                },
                .src_addr = reg.address(),
                .dst_addr = info_va + i * @sizeOf(pm4.Word),
            });
        }
    }

    cmdbuf.setUConfigReg(.grbm_gfx_index, .{
        .instance_index = 0,
        .sa_index = 0,
        .se_index = 0,
        .sa_broadcast_writes = true,
        .instance_broadcast_writes = true,
        .se_broadcast_writes = true,
    });

    cmdbuf.setUConfigReg(.spi_config_cntl, .{
        .gpr_write_priority = 0x2c688,
        .exp_priority_order = 3,
        .enable_sqg_top_events = true,
        .enable_sqg_bop_events = true,
        .rsrc_mgmt_reset = false,
        .ttrace_stall_all = false,
        .alloc_arb_lru_ena = false,
        .exp_arb_lru_ena = false,
        .ps_pkr_priority_cntl = 3,
    });

    // TODO: Find out previous state
    cmdbuf.setUConfigReg(.rlc_perfmon_clock_cntl, .{
        .inhibit_clock = false,
    });

    return cmdbuf.words();
}

/// Fetches the trace information from the GPU. `agent_info` must be the
/// the same as that passed to `init`. The returned traces must be deinitialized
/// using `deinit(a)`.
pub fn read(self: *Self, a: Allocator, agent_info: AgentInfo) ![]Trace {
    const shader_engines = agent_info.properties.shader_engines;
    const output_va = @intFromPtr(self.output_buffer.ptr);
    var shader_engine: u32 = 0;
    var traces = std.ArrayList(Trace).init(a);
    defer traces.deinit();
    while (shader_engine < shader_engines) : (shader_engine += 1) {
        // Note: logic for selecting SEs and CUs to use should be kept the same as in startCommands.
        const info_va = output_va + threadTraceInfoOffset(shader_engine);
        const data_va = output_va + threadTraceDataOffset(thread_trace_buffer_size, shader_engine, shader_engines);
        const first_active_cu = 0;

        // Data pointer is mapped to CPU, so we can just copy it directly.
        const info: *const ThreadTraceInfo = @ptrFromInt(info_va);
        const data = @as([*]const u8, @ptrFromInt(data_va))[0 .. info.cur_offset * 32];

        std.log.debug("se {}: trace used {} out of {} bytes", .{ shader_engine, data.len, thread_trace_buffer_size });

        try traces.append(.{
            .info = info.*,
            .data = try a.dupe(u8, data),
            .shader_engine = shader_engine,
            .compute_unit = first_active_cu,
        });
    }

    return try traces.toOwnedSlice();
}
