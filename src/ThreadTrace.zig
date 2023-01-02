//! This module contains stuff that deals with gathering the actual thread trace.
const Self = @This();

const std = @import("std");
const Allocator = std.mem.Allocator;

const pm4 = @import("pm4.zig");
const hsa = @import("hsa.zig");
const CmdBuf = @import("CmdBuf.zig");
const AgentInfo = @import("Profiler.zig").AgentInfo;

/// The default size of the thread trace buffer, values taken from rocprof/mesa.
const thread_trace_buffer_size = 32 * 1024 * 1024;

/// The default size for the start command buffer. Increase as needed, but should be aligned
/// to page size (0x1000) in bytes. Note: size is in words.
const start_cmd_size = 0x400;
/// The default size for the stop command buffer. Increase as needed, but should be aligned
/// to page size (0x1000) in bytes. Note: size is in words.
const stop_cmd_size = 0x400;

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
    /// The compute unit on the shader engien that this trace was recorded for.
    compute_unit: u32,

    pub fn deinit(self: *Trace, a: Allocator) void {
        a.free(self.data);
        self.* = undefined;
    }
};

/// This is a HSA-compatible packet used for thread tracing.
/// Actually, this structure is the same as hsa_ext_amd_aql_pm4_packet_t,
/// but just a bit touched up for us to use.
/// Note: This packet is different for GFX <= 8. Check AMDPAL for its structure
/// in that situation.
pub const Packet = extern struct {
    comptime {
        std.debug.assert(@sizeOf(Packet) == hsa.Packet.alignment);
    }

    const pm4_size = 4;

    /// Sub-type of this packet
    pub const Type = enum(u16) {
        // PM4 'indirect_buffer' command. Only the indirect buffer command may
        // be placed in the pm4 data, it seems.
        pm4_ib = 0x1,
    };

    /// HSA packet header, set to 0 for vendor-specific packet.
    header: hsa.Packet.Header,
    /// Vendor-specific-packet header.
    ven_hdr: Type,
    /// The actual PM4 command for this packet. It seems that there can only be one
    /// type of command here, corresponding to the ven_hdr, of which currently only
    /// the IB command is known.
    pm4: [pm4_size]pm4.Word,
    /// The amount of words that remain
    dw_remain: u32,
    /// Padding
    _reserved: [8]u32 = .{0} ** 8,
    /// Signal that probably gets ringed if this packet has been finished executing or something.
    completion_signal: hsa.Signal,

    fn init(ib: []const pm4.Word) Packet {
        var packet = Packet{
            .header = .{
                .packet_type = .vendor_specific,
                .barrier = 0,
                .acquire_fence_scope = 0,
                .release_fence_scope = 0,
            },
            .ven_hdr = .pm4_ib,
            .pm4 = .{0} ** pm4_size,
            .dw_remain = 0xA,
            .completion_signal = .{ .handle = 0 },
        };
        var cmdbuf = CmdBuf{
            .cap = Packet.pm4_size,
            .buf = &packet.pm4,
        };
        cmdbuf.indirectBuffer(ib);
        return packet;
    }

    pub fn asHsaPacket(self: *const Packet) *const hsa.Packet {
        return @ptrCast(*const hsa.Packet, self);
    }
};

output_buffer: []u8,

start_ib: []pm4.Word,
start_packet: Packet,

stop_ib: []pm4.Word,
stop_packet: Packet,

pub fn init(
    instance: *const hsa.Instance,
    cpu_pool: hsa.MemoryPool,
    agent_info: AgentInfo,
) !Self {
    const output_buffer = try instance.memoryPoolAllocate(
        u8,
        cpu_pool,
        threadTraceBufferSize(agent_info.shader_engines, thread_trace_buffer_size),
    );
    std.mem.set(u8, output_buffer, 0);
    errdefer instance.memoryPoolFree(output_buffer);
    instance.agentsAllowAccess(output_buffer.ptr, &.{agent_info.agent});

    const start_ib = try startCommands(instance, cpu_pool, agent_info.shader_engines, output_buffer);
    errdefer instance.memoryPoolFree(start_ib);
    instance.agentsAllowAccess(start_ib.ptr, &.{agent_info.agent});

    const stop_ib = try stopCommands(instance, cpu_pool, agent_info.shader_engines, output_buffer);
    errdefer instance.memoryPoolFree(stop_ib);
    instance.agentsAllowAccess(stop_ib.ptr, &.{agent_info.agent});

    var self = Self{
        .output_buffer = output_buffer,
        .start_ib = start_ib,
        .start_packet = Packet.init(start_ib),
        .stop_ib = stop_ib,
        .stop_packet = Packet.init(stop_ib),
    };
    self.stop_packet.completion_signal = try instance.createSignal(1, &.{});
    return self;
}

pub fn deinit(self: *Self, instance: *const hsa.Instance) void {
    instance.memoryPoolFree(self.output_buffer.ptr);
    instance.destroySignal(self.stop_packet.completion_signal);
    self.* = undefined;
}

fn threadTraceBufferSize(shader_engines: u32, per_trace_buffer_size: u32) u32 {
    const aligned_buffer_size = std.mem.alignForward(per_trace_buffer_size, sqtt_buffer_align);
    const size = std.mem.alignForward(@sizeOf(ThreadTraceInfo) * shader_engines, sqtt_buffer_align) +
        aligned_buffer_size * shader_engines;
    return @intCast(u32, size);
}

fn threadTraceInfoOffset(shader_engine: u32) usize {
    return @sizeOf(ThreadTraceInfo) * shader_engine;
}

fn threadTraceDataOffset(per_trace_buffer_size: u32, shader_engine: u32, shader_engines: u32) usize {
    var data_offset = std.mem.alignForward(@sizeOf(ThreadTraceInfo) * shader_engines, sqtt_buffer_align);
    data_offset += std.mem.alignForward(per_trace_buffer_size, sqtt_buffer_align) * shader_engine;
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
    const output_va = @ptrToInt(output_buffer.ptr);

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
            .se_index = @intCast(u8, shader_engine),
            .sa_broadcast_writes = false,
            .instance_broadcast_writes = true,
            .se_broadcast_writes = false,
        });

        // Assume gfx >= 10
        // Note: order is apparently important for the following 2 registers.
        cmdbuf.setPrivilegedConfigReg(.sqtt_buf0_size, .{
            .size = @intCast(u24, shifted_size),
            .base_hi = @intCast(u8, shifted_va >> 32),
        });
        cmdbuf.setPrivilegedConfigReg(.sqtt_buf0_base, @truncate(u32, shifted_va));

        cmdbuf.setPrivilegedConfigReg(.sqtt_mask, .{
            .wtype_include = 0x7F,
            .sa_sel = 0,
            .wgp_sel = @intCast(u1, first_active_cu / 2),
            .simd_sel = 0,
        });

        cmdbuf.setPrivilegedConfigReg(.sqtt_token_mask, .{
            .token_exclude = .{
                .perf = true,
            },
            .bop_events_token_include = false,
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
            .reg_detail_all = 0,
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
            .reg_drop_on_stall = true,
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

    cmdbuf.setShReg(.compute_thread_trace_enable, .{
        .enable = false,
    });

    cmdbuf.writeEventNonSample(.thread_trace_finish, 0);

    var shader_engine: u32 = 0;
    while (shader_engine < shader_engines) : (shader_engine += 1) {
        cmdbuf.setUConfigReg(.grbm_gfx_index, .{
            .instance_index = 0,
            .sa_index = 0,
            .se_index = @intCast(u8, shader_engine),
            .sa_broadcast_writes = false,
            .instance_broadcast_writes = true,
            .se_broadcast_writes = false,
        });

        const sqtt_status = pm4.PrivilegedRegister.sqtt_status;
        // _ = output_buffer;
        // _ = sqtt_status;

        // TODO: This hangs, but doesnt seem to prevent anything from appearing in the output...
        // Poll the status register to ensure that the thread trace has finished writing.
        // cmdbuf.waitRegMem(.{
        //     .function = .ne,
        //     .mem_space = .register,
        //     .engine = .me,
        //     .poll_addr = sqtt_status.address(),
        //     .reference = 0,
        //     .mask = @bitCast(u32, sqtt_status.Type(){
        //         .finish_done = std.math.maxInt(u12),
        //     }),
        //     .poll_interval = 4,
        // });

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
            .reg_drop_on_stall = true,
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
            .mask = @bitCast(u32, sqtt_status.Type(){
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
        const va = @ptrToInt(output_buffer.ptr);
        const info_va = va + threadTraceInfoOffset(shader_engine);

        for (info_regs) |reg, i| {
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

    return cmdbuf.words();
}

/// Fetches the trace information from the GPU. `agent_info` must be the
/// the same as that passed to `init`. Traces will be added to `out`, and
/// each trace must be deinitialized using `a`.
pub fn read(self: *Self, out: *std.ArrayList(Trace), a: Allocator, agent_info: AgentInfo) !void {
    const shader_engines = agent_info.shader_engines;
    const output_va = @ptrToInt(self.output_buffer.ptr);
    var shader_engine: u32 = 0;
    while (shader_engine < shader_engines) : (shader_engine += 1) {
        // Note: logic for selecting SEs and CUs to use should be kept the same as in startCommands.
        const info_va = output_va + threadTraceInfoOffset(shader_engine);
        const data_va = output_va + threadTraceDataOffset(thread_trace_buffer_size, shader_engine, shader_engines);
        const first_active_cu = 0;

        // Data pointer is mapped to CPU, so we can just copy it directly.
        const info = @intToPtr(*const ThreadTraceInfo, info_va);
        const data = @intToPtr([*]const u8, data_va)[0 .. info.cur_offset * 32];

        try out.append(.{
            .info = info.*,
            .data = try a.dupe(u8, data),
            .shader_engine = shader_engine,
            .compute_unit = first_active_cu,
        });
    }
}
