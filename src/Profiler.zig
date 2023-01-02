const Profiler = @This();

const std = @import("std");
const hsa = @import("hsa.zig");
const rgp = @import("rgp.zig");
const ThreadTrace = @import("ThreadTrace.zig");

const stop_trace_signal_timeout_ns = std.time.ns_per_s * 10;

/// A proxy HSA queue that we can use to intercept HSA packets.
pub const ProfileQueue = struct {
    /// The index of the agent that created this queue, into `agents`.
    agent: usize,
    /// The real queue that commands will be submitted to.
    backing_queue: *hsa.Queue,
    /// The HSA handle for this proxying queue.
    queue: hsa.Queue,
    /// The read index for the queue's ring buffer.
    read_index: u64,
    /// The write index for the queue's ring buffer.
    write_index: u64,
    /// Thread trace data.
    thread_trace: ThreadTrace,

    pub fn packetBuffer(self: *ProfileQueue) []align(hsa.Packet.alignment) hsa.Packet {
        return @ptrCast(
            [*]align(hsa.Packet.alignment) hsa.Packet,
            @alignCast(hsa.Packet.alignment, self.queue.base_address.?),
        )[0..self.queue.size];
    }

    fn backingPacketBuffer(self: *ProfileQueue) []align(hsa.Packet.alignment) hsa.Packet {
        return @ptrCast(
            [*]align(hsa.Packet.alignment) hsa.Packet,
            @alignCast(hsa.Packet.alignment, self.backing_queue.base_address.?),
        )[0..self.backing_queue.size];
    }
};

/// Meta-information tho avoid having it to query all the time.
pub const AgentInfo = struct {
    /// The AMD architecture level. This value is the architecture in hexadecimal (eg, 0x1030 for gfx1030).
    /// If this is not applicable for the current agent, its .not_applicable.
    pub const GcnArch = enum(u32) {
        not_applicable = 0,
        // Common ones can be added here, for utility.
        gfx1030 = 0x1030,
        _,

        pub fn major(self: GcnArch) u32 {
            return @enumToInt(self) >> 8;
        }

        pub fn minor(self: GcnArch) u32 {
            return (@enumToInt(self) >> 4) & 0xF;
        }
    };

    /// The agent that this information concerns. Will be used as key for the `agents` map.
    agent: hsa.Agent,
    /// Name of agent, zero-terminated (max 63 chars).
    name: [64]u8,
    /// The type of the agent. Thread traces will only be valid for queues created for a gpu agent.
    agent_type: hsa.DeviceType,
    /// The primary (device-local) pool to allocate memory from for this agent.
    primary_pool: hsa.MemoryPool,
    /// The number of shader engines that this agent has. This is here so that we
    /// dont have to query it all the time.
    shader_engines: u32,
    /// The agent's GCN architecture level. If this is a cpu agent, this is .not_applicable.
    gcn_arch: GcnArch,

    pub const HashContext = struct {
        pub fn hash(self: @This(), agent_info: AgentInfo) u32 {
            _ = self;
            return @truncate(u32, std.hash.Wyhash.hash(0, std.mem.asBytes(&agent_info.agent.handle)));
        }

        pub fn eql(self: @This(), a: AgentInfo, b: AgentInfo, b_index: usize) bool {
            _ = self;
            _ = b_index;
            return a.agent.handle == b.agent.handle;
        }
    };

    pub const HashContextByAgent = struct {
        pub fn hash(self: @This(), agent: hsa.Agent) u32 {
            _ = self;
            return @truncate(u32, std.hash.Wyhash.hash(0, std.mem.asBytes(&agent.handle)));
        }

        pub fn eql(self: @This(), agent: hsa.Agent, agent_info: AgentInfo, b_index: usize) bool {
            _ = self;
            _ = b_index;
            return agent.handle == agent_info.agent.handle;
        }
    };
};

/// The allocator to use for profiling data.
a: std.mem.Allocator,
/// The HSA instance that we call into.
instance: hsa.Instance,
/// A map of agents and some useful information about them.
agents: std.ArrayHashMapUnmanaged(AgentInfo, void, AgentInfo.HashContext, true) = .{},
/// The CPU agent that we use to allocate host resources, such as CPU-GPU
/// shared memory etc. Index into `agents`.
cpu_agent: u32,
/// A map of queue handles to queue proxy queues. A queue is identified by its doorbell signal.
/// TODO: we can get rid of the duplicate signal handle by using a context.
queues: std.AutoArrayHashMapUnmanaged(hsa.Signal, *ProfileQueue) = .{},

pub fn init(a: std.mem.Allocator, api_table: *const hsa.ApiTable) !Profiler {
    var self = Profiler{
        .a = a,
        .instance = hsa.Instance.init(api_table),
        .cpu_agent = undefined,
    };
    try self.queryAgents();
    return self;
}

pub fn deinit(self: *Profiler) void {
    // for (self.queues.items()) |pq| {
    //     pq.trace.deinit(self.a);
    // }

    self.agents.deinit(self.a);
    self.queues.deinit(self.a);
    self.* = undefined;
}

fn queryAgents(self: *Profiler) !void {
    _ = try self.instance.iterateAgents(self, queryAgentsCbk);

    self.cpu_agent = for (self.agents.keys()) |info, i| {
        if (info.agent_type == .cpu)
            break @intCast(u32, i);
    } else {
        std.log.err("system has no cpu agent", .{});
        return error.Genric;
    };
}

fn queryAgentsCbk(self: *Profiler, agent: hsa.Agent) !?void {
    const result = self.agents.getOrPut(self.a, AgentInfo{
        .agent = agent,
        // Fields are filled in momentarily.
        .name = undefined,
        .agent_type = undefined,
        .primary_pool = undefined,
        .shader_engines = undefined,
        .gcn_arch = .not_applicable,
    }) catch return error.OutOfResources;
    std.debug.assert(!result.found_existing); // bug in HSA: the same agent is reported twice.
    const info = result.key_ptr;

    info.name = self.instance.getAgentInfo(agent, .name);
    info.agent_type = self.instance.getAgentInfo(agent, .device_type);
    info.shader_engines = self.instance.getAgentInfo(agent, .num_shader_engines);

    const name = std.mem.sliceTo(&info.name, 0);
    const type_str = switch (info.agent_type) {
        .cpu => "cpu",
        .gpu => "gpu",
        _ => "other",
    };
    std.log.info("found device '{s}' of type {s}", .{ name, type_str });

    if (std.mem.startsWith(u8, name, "gfx")) {
        // Try to parse the remainder as gfx architecture level. These are in the form
        // `gfxX` where X are 3 or 4 hexadecimal chars. We're just going to cheat and
        // interpret the rest of the string as hex.
        if (std.fmt.parseInt(u32, name[3..], 16)) |arch_level| {
            info.gcn_arch = @intToEnum(AgentInfo.GcnArch, arch_level);
        } else |_| {
            std.log.warn("could not parse gfx-like device name '{s}' as gcn arch level", .{name});
        }
    }

    info.primary_pool = (try self.instance.iterateMemoryPools(agent, self, queryAgentPoolsCbk)) orelse {
        std.log.err("failed to find a suitable primary memory pool for agent 0x{x} ({s})", .{ info.agent.handle, name });
        return error.Generic;
    };

    return null;
}

fn queryAgentPoolsCbk(self: *Profiler, pool: hsa.MemoryPool) !?hsa.MemoryPool {
    const segment = self.instance.getMemoryPoolInfo(pool, .segment);
    if (segment != .global)
        return null;

    const runtime_alloc_allowed = self.instance.getMemoryPoolInfo(pool, .runtime_alloc_allowed);
    if (!runtime_alloc_allowed)
        return null;

    return pool;
}

/// Add tracking information for a HSA queue, after it has been created.
pub fn createQueue(
    self: *Profiler,
    agent: hsa.Agent,
    size: u32,
    queue_type: hsa.QueueType32,
    callback: ?*const fn (hsa.Status, [*c]hsa.Queue, ?*anyopaque) callconv(.C) void,
    data: ?*anyopaque,
    private_segment_size: u32,
    group_segment_size: u32,
) !*hsa.Queue {
    _ = queue_type;
    _ = callback;
    _ = data;
    _ = private_segment_size;
    _ = group_segment_size;

    const backing_queue = try self.instance.createQueue(
        agent,
        size,
        .multi,
        null, // This is what rocprof does. Maybe this needs to be properly converted?
        null, // This is what rocprof does.
        std.math.maxInt(u32), // This is what rocprof does.
        std.math.maxInt(u32), // This is what rocprof does.
    );
    errdefer self.instance.destroyQueue(backing_queue);

    // Create our own packet buffer, doorbell, etc.
    const doorbell = try self.instance.createSignal(1, &.{});
    errdefer self.instance.destroySignal(doorbell);

    const packet_buf = try self.a.allocWithOptions(hsa.Packet, size, hsa.Packet.alignment, null);
    errdefer self.a.free(packet_buf);

    const gpu_agent_index = self.agents.getIndexAdapted(agent, AgentInfo.HashContextByAgent{}).?;
    const gpu_agent_info = self.agents.keys()[gpu_agent_index];
    const cpu_agent_info = self.agents.keys()[self.cpu_agent];
    var thread_trace = try ThreadTrace.init(
        &self.instance,
        cpu_agent_info.primary_pool,
        gpu_agent_info,
    );
    errdefer thread_trace.deinit(&self.instance);

    const pq = try self.a.create(ProfileQueue); // Needs to be pinned in memory.
    pq.* = ProfileQueue{
        .agent = gpu_agent_index,
        .backing_queue = backing_queue,
        .queue = .{
            .type = backing_queue.*.type,
            .features = backing_queue.*.features,
            .base_address = packet_buf.ptr,
            .doorbell_signal = doorbell,
            .size = size,
            .reserved1 = 0,
            .id = backing_queue.*.id,
        },
        .read_index = 0,
        .write_index = 0,
        .thread_trace = thread_trace,
    };

    const result = try self.queues.getOrPut(self.a, doorbell);
    if (result.found_existing) {
        // Should never happen.
        unreachable;
    }
    result.value_ptr.* = pq;
    return &pq.queue;
}

/// Remove tracking information for a HSA queue, after it has been destroyed.
pub fn destroyQueue(self: *Profiler, queue: *hsa.Queue) !void {
    const pq = self.getProfileQueue(queue) orelse return error.InvalidQueue;
    pq.thread_trace.deinit(&self.instance);
    self.instance.destroyQueue(pq.backing_queue);
    self.instance.destroySignal(pq.queue.doorbell_signal);
    self.a.free(pq.packetBuffer());
    self.a.destroy(pq);
}

/// Submit a generic packet to the backing queue of a ProfileQueue. This function may block until
/// there is enough room for the packet.
pub fn submit(self: *Profiler, pq: *ProfileQueue, packet: *const hsa.Packet) void {
    const queue = pq.backing_queue;
    const write_index = self.instance.queueAddWriteIndex(queue, 1, .AcqRel);

    // Busy loop until there is space.
    // TODO: Maybe this can be improved or something?
    while (write_index - self.instance.queueLoadReadIndex(queue, .Monotonic) >= queue.size) {
        continue;
    }

    const slot_index = @intCast(u32, write_index % queue.size);
    const slot = &pq.backingPacketBuffer()[slot_index];

    // AQL packets have an 'invalid' header, which indicates that there is no packet at this
    // slot index yet - we want to overwrite that last, so that the packet is not read before
    // it is completely written.
    const packet_bytes = std.mem.asBytes(packet);
    const slot_bytes = std.mem.asBytes(slot);
    std.mem.copy(u8, slot_bytes[2..], packet_bytes[2..]);
    // Write the packet header atomically.
    @atomicStore(u16, @ptrCast(*u16, &slot.header), @bitCast(u16, packet.header), .Release);

    // Finally, ring the doorbell to notify the agent of the updated packet.
    self.instance.signalStore(queue.doorbell_signal, @intCast(hsa.SignalValue, write_index), .Monotonic);
}

/// Turn an HSA queue handle into its associated ProfileQueue, if that exists.
pub fn getProfileQueue(self: *Profiler, queue: *const hsa.Queue) ?*ProfileQueue {
    return self.queues.get(queue.doorbell_signal);
}

/// Start tracing.
pub fn startTrace(self: *Profiler, pq: *ProfileQueue) void {
    // The stuff done in this function is mainly based on
    // https://github.com/Mesa3D/mesa/blob/main/src/amd/vulkan/radv_sqtt.c
    // TODO: Find out what we need to bring over. For now, we only target GFX10
    // and the stuff from radv_emit_thread_trace_start.
    std.log.info("starting kernel trace", .{});
    self.submit(pq, pq.thread_trace.start_packet.asHsaPacket());
}

/// Stop tracing.
pub fn stopTrace(self: *Profiler, pq: *ProfileQueue) !void {
    std.log.info("stopping kernel trace", .{});
    self.submit(pq, pq.thread_trace.stop_packet.asHsaPacket());

    // Wait until the stop trace packet has been processed.
    while (true) {
        const value = self.instance.signalWait(
            pq.thread_trace.stop_packet.completion_signal,
            .lt,
            1,
            stop_trace_signal_timeout_ns,
            .blocked,
            .Acquire,
        );
        switch (value) {
            0 => break,
            1 => {},
            else => std.log.err("invalid signal value", .{}),
        }
    }
    self.instance.signalStore(pq.thread_trace.stop_packet.completion_signal, 1, .Monotonic);

    const cpu_agent_info = self.agents.keys()[self.cpu_agent];
    const gpu_agent_info = self.agents.keys()[pq.agent];

    var traces = std.ArrayList(ThreadTrace.Trace).init(self.a);
    defer {
        for (traces.items) |*trace| {
            trace.deinit(self.a);
        }
        traces.deinit();
    }
    try pq.thread_trace.read(&traces, self.a, gpu_agent_info);

    rgp.dumpCapture(
        "dump.rgp",
        &self.instance,
        cpu_agent_info,
        gpu_agent_info,
        traces.items,
    ) catch |err| {
        std.log.err("failed to save capture: {s}", .{@errorName(err)});
        return error.Save;
    };
}

/// Dispatch a kernel packet. This function makes sure to record the relevant info in the queue's trace.
pub fn dispatchKernel(
    self: *Profiler,
    pq: *ProfileQueue,
    packet: *align(hsa.Packet.alignment) const hsa.KernelDispatchPacket,
) void {
    // Obtain the AMD kernel code handle for this packet.
    // TODO: Make sure that this is a device queue?
    const kernel_code = self.instance.loaderQueryHostAddress(
        hsa.AmdKernelCode,
        @intToPtr(*const hsa.AmdKernelCode, packet.kernel_object),
    );
    std.log.debug("{}", .{kernel_code});

    self.submit(pq, @ptrCast(*align(hsa.Packet.alignment) const hsa.Packet, packet));
}
