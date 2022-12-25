//! This module contains stuff that deals with gathering the actual thread trace.
const Self = @This();

const std = @import("std");
const c = @import("c.zig");
const pm4 = @import("pm4.zig");
const hsa_util = @import("hsa_util.zig");
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

/// Taken from mesa.
const ThreadTraceInfo = extern struct {
    cur_offset: u32,
    trace_status: u32,
    arch: extern union {
        gfx9_write_counter: u32,
        gfx10_dropped_cntr: u32,
    },
};

/// This is a HSA-compatible packet used for thread tracing.
/// Actually, this structure is the same as hsa_ext_amd_aql_pm4_packet_t,
/// but just a bit touched up for us to use.
pub const Packet = extern struct {
    comptime {
        std.debug.assert(@sizeOf(Packet) == c.hsa_packet_t.alignment);
    }

    const pm4_size = 13;

    /// HSA packet header, set to 0 for vendor-specific packet.
    header: u16,
    /// Not sure yet if this is really the number of pm4 packets, but when the
    /// indirect buffer command is there this is set to 1 and if there is no command
    /// there it is set to 0.
    maybe_number_of_packets: u16 = 1,
    /// The actual PM4 commands. There is only enough space for a few here, which is
    /// this is only going to contain an `indirect_buffer` command to invoke a
    /// secondary command buffer which is able to be stored on-heap and so
    /// able to have more commands.
    pm4: [pm4_size]pm4.Word,
    /// Signal that probably gets ringed if this packet has been finished executing or something.
    completion_signal: c.hsa_signal_t,

    fn init(ib: []const pm4.Word) Packet {
        var packet = Packet{
            .header = 0,
            .pm4 = .{0} ** pm4_size,
            .completion_signal = .{ .handle = 0 },
        };
        var cmdbuf = CmdBuf{
            .cap = Packet.pm4_size,
            .buf = &packet.pm4,
        };
        cmdbuf.indirectBuffer(ib);
        // IDK why this is required, but aqlprofile does it in rocprof.
        cmdbuf.weirdAqlProfilePacketStreamTerminator();
        return packet;
    }

    fn initWithSignal(hsa: *const c.CoreApiTable, ib: []const pm4.Word) !Packet {
        var self = Packet.init(ib);
        try hsa_util.check(hsa.signal_create(1, 0, null, &self.completion_signal));
        return self;
    }

    pub fn asHsaPacket(self: *const Packet) *const c.hsa_packet_t {
        return @ptrCast(*const c.hsa_packet_t, self);
    }
};

output_buffer: []u8,

start_ib: []pm4.Word,
start_packet: Packet,

stop_ib: []pm4.Word,
stop_packet: Packet,

pub fn init(
    hsa: *const c.CoreApiTable,
    hsa_amd: *const c.AmdExtTable,
    cpu_pool: c.hsa_amd_memory_pool_t,
    agent: c.hsa_agent_t,
    agent_info: AgentInfo,
) !Self {
    const output_buffer = try hsa_util.alloc(
        hsa_amd,
        cpu_pool,
        threadTraceBufferSize(agent_info.shader_engines orelse 1, thread_trace_buffer_size),
    );
    errdefer hsa_util.free(hsa_amd, output_buffer);
    try hsa_util.allowAccess(hsa_amd, output_buffer.ptr, &.{agent});

    const start_ib = try startCommands(hsa_amd, cpu_pool);
    try hsa_util.allowAccess(hsa_amd, start_ib.ptr, &.{agent});

    const stop_ib = try stopCommands(hsa_amd, cpu_pool);
    try hsa_util.allowAccess(hsa_amd, stop_ib.ptr, &.{agent});

    var self = Self{
        .output_buffer = output_buffer,
        .start_ib = start_ib,
        .start_packet = Packet.init(start_ib),
        .stop_ib = stop_ib,
        .stop_packet = try Packet.initWithSignal(hsa, stop_ib),
    };
    return self;
}

pub fn deinit(self: *Self, hsa: *const c.CoreApiTable, hsa_amd: *const c.AmdExtTable) void {
    hsa_util.free(hsa_amd, self.output_buffer);
    std.debug.assert(hsa.signal_destroy(self.stop_packet.completion_signal) == c.HSA_STATUS_SUCCESS);
    self.* = undefined;
}

fn threadTraceBufferSize(shader_engines: u32, per_trace_buffer_size: u32) u32 {
    const aligned_buffer_size = std.mem.alignForward(per_trace_buffer_size, sqtt_buffer_align);
    const size = std.mem.alignForward(@sizeOf(ThreadTraceInfo) * shader_engines, sqtt_buffer_align) +
        aligned_buffer_size * shader_engines;
    return @intCast(u32, size);
}

fn startCommands(hsa_amd: *const c.AmdExtTable, cpu_pool: c.hsa_amd_memory_pool_t) ![]pm4.Word {
    var cmdbuf = try CmdBuf.alloc(hsa_amd, cpu_pool, start_cmd_size);
    errdefer cmdbuf.free(hsa_amd);
    cmdbuf.nop();
    return cmdbuf.words();
}

fn stopCommands(hsa_amd: *const c.AmdExtTable, cpu_pool: c.hsa_amd_memory_pool_t) ![]pm4.Word {
    var cmdbuf = try CmdBuf.alloc(hsa_amd, cpu_pool, stop_cmd_size);
    errdefer cmdbuf.free(hsa_amd);
    cmdbuf.nop();
    return cmdbuf.words();
}
