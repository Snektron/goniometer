//! This module contains stuff that deals with gathering the actual thread trace.
const Self = @This();

const std = @import("std");
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
        std.debug.assert(@sizeOf(Packet) == hsa.Packet.alignment);
    }

    const pm4_size = 13;

    /// HSA packet header, set to 0 for vendor-specific packet.
    header: hsa.Packet.Header,
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
    completion_signal: hsa.Signal,

    fn init(ib: []const pm4.Word) Packet {
        var packet = Packet{
            .header = .{
                .packet_type = .vendor_specific,
                .barrier = 0,
                .acquire_fence_scope = 0,
                .release_fence_scope = 0,
            },
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
    agent: hsa.Agent,
) !Self {
    const shader_engines = instance.getAgentInfo(agent, .num_shader_engines);
    const output_buffer = try instance.memoryPoolAllocate(
        u8,
        cpu_pool,
        threadTraceBufferSize(shader_engines, thread_trace_buffer_size),
    );
    errdefer instance.memoryPoolFree(output_buffer);
    instance.agentsAllowAccess(output_buffer.ptr, &.{agent});

    const start_ib = try startCommands(instance, cpu_pool);
    errdefer instance.memoryPoolFree(start_ib);
    instance.agentsAllowAccess(start_ib.ptr, &.{agent});

    const stop_ib = try stopCommands(instance, cpu_pool);
    errdefer instance.memoryPoolFree(stop_ib);
    instance.agentsAllowAccess(stop_ib.ptr, &.{agent});

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

fn startCommands(instance: *const hsa.Instance, cpu_pool: hsa.MemoryPool) ![]pm4.Word {
    var cmdbuf = try CmdBuf.alloc(instance, cpu_pool, start_cmd_size);
    errdefer cmdbuf.free(instance);
    cmdbuf.nop();
    return cmdbuf.words();
}

fn stopCommands(instance: *const hsa.Instance, cpu_pool: hsa.MemoryPool) ![]pm4.Word {
    var cmdbuf = try CmdBuf.alloc(instance, cpu_pool, stop_cmd_size);
    errdefer cmdbuf.free(instance);
    cmdbuf.nop();
    return cmdbuf.words();
}
