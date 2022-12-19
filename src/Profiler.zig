const Profiler = @This();

const std = @import("std");
const c = @import("c.zig");
const hsa_util = @import("hsa_util.zig");

/// A proxy HSA queue that we can use to intercept HSA packets.
pub const ProfileQueue = struct {
    /// The agent that created this queue
    agent: c.hsa_agent_t,
    /// The real queue that commands will be submitted to.
    backing_queue: *c.hsa_queue_t,
    /// The HSA handle for this proxying queue.
    queue: c.hsa_queue_t,
    /// The read index for the queue's ring buffer.
    read_index: u64,
    /// The write index for the queue's ring buffer.
    write_index: u64,

    pub fn packetBuffer(self: *ProfileQueue) []c.hsa_packet_t {
        return @ptrCast(
            [*]c.hsa_packet_t,
            @alignCast(c.hsa_packet_t.alignment, self.queue.base_address.?),
        )[0..self.queue.size];
    }

    pub fn backingPacketBuffer(self: *ProfileQueue) []c.hsa_packet_t {
        return @ptrCast(
            [*]c.hsa_packet_t,
            @alignCast(c.hsa_packet_t.alignment, self.backing_queue.base_address.?
        ))[0..self.backing_queue.size];
    }
};

/// Meta-information tho avoid having it to query all the time.
pub const AgentInfo = struct {
    /// The type of this agent
    agent_type: c.hsa_device_type_t,
    /// The primary (device-local) pool to allocate memory from for this agent.
    primary_pool: c.hsa_amd_memory_pool_t,
    /// The number of shader engines in this agent. Only valid if
    /// `agent_type` is GPU.
    shader_engines: u32,
};

/// The allocator to use for profiling data.
a: std.mem.Allocator,
/// The api table that we can use to invoke HSA functions.
hsa: c.CoreApiTable,
/// The api table for the AMD extension functionality.
hsa_amd: c.AmdExtTable,
/// Dynamically loaded libhsa-amd-aqlprofile.
aqlprofile: struct {
    lib: std.DynLib,
    start: *const @TypeOf(c.hsa_ven_amd_aqlprofile_start),
},
/// A map of agents and some useful information about them.
agents: std.AutoArrayHashMapUnmanaged(c.hsa_agent_t, AgentInfo) = .{},
/// The CPU agent that we use to allocate host resources, such as CPU-GPU
/// shared memory etc. Index into `agents`.
cpu_agent: u32,
/// A map of queue handles to queue proxy queues. A queue is identified by its doorbell signal.
/// TODO: we can get rid of the duplicate signal handle by using a context.
queues: std.AutoArrayHashMapUnmanaged(c.hsa_signal_t, *ProfileQueue) = .{},

pub fn init(a: std.mem.Allocator, hsa: *c.ApiTable) !Profiler {
    var self = Profiler{
        .a = a,
        .hsa = hsa.core.*,
        .hsa_amd = hsa.amd_ext.*,
        .aqlprofile = undefined,
        .cpu_agent = undefined,
    };
    self.aqlprofile.lib = std.DynLib.open(&c.kAqlProfileLib) catch |err| {
        std.log.err("failed to load aqlprofile library {s}: {s}", .{ &c.kAqlProfileLib, @errorName(err) });
        return error.AqlProfileLoadFailure;
    };
    errdefer self.aqlprofile.lib.close();

    self.aqlprofile.start = self.aqlprofile.lib.lookup(
        *const @TypeOf(c.hsa_ven_amd_aqlprofile_start),
        "hsa_ven_amd_aqlprofile_start",
    ) orelse return error.AqlProfileMissingLibraryFunction;

    try self.queryAgents();

    return self;
}

pub fn deinit(self: *Profiler) void {
    self.aqlprofile.lib.close();
    self.* = undefined;
}

fn queryAgents(self: *Profiler) !void {
    const status = self.hsa.iterate_agents(&queryAgentsCbk, self);
    if (status != c.HSA_STATUS_SUCCESS) {
        return error.HsaError;
    }

    for (self.agents.keys()) |agent, i| {
        var name_buf: [64]u8 = undefined;
        try hsa_util.check(self.hsa.agent_get_info(agent, c.HSA_AGENT_INFO_NAME, &name_buf));
        const name = std.mem.sliceTo(&name_buf, 0);

        var agent_type: c.hsa_device_type_t = undefined;
        try hsa_util.check(self.hsa.agent_get_info(agent, c.HSA_AGENT_INFO_DEVICE, &agent_type));

        const type_str = switch (agent_type) {
            c.HSA_DEVICE_TYPE_CPU => "cpu",
            c.HSA_DEVICE_TYPE_GPU => "gpu",
            else => "other",
        };

        std.log.info("system has agent '{s}' of type {s}", .{ name, type_str });

        var shader_engines: u32 = undefined;
        switch (agent_type) {
            c.HSA_DEVICE_TYPE_CPU => {
                self.cpu_agent = @intCast(u32, i);
            },
            c.HSA_DEVICE_TYPE_GPU => {
                try hsa_util.check(self.hsa.agent_get_info(agent, c.HSA_AMD_AGENT_INFO_NUM_SHADER_ENGINES, &shader_engines));
            },
            else => {},
        }

        var ctx = QueryAgentPoolsCtx{
            .profiler = self,
            .agent = agent,
            .primary_pool = undefined,
        };
        switch (c.hsa_amd_agent_iterate_memory_pools(agent, QueryAgentPoolsCtx.cbk, &ctx)) {
            c.HSA_STATUS_INFO_BREAK => {},
            // Success but no break means no pool found.
            c.HSA_STATUS_SUCCESS => {
                std.log.err("failed to find a suitable primary memory pool for agent {} ({s})", .{ agent.handle, name });
                return error.Generic;
            },
            else => |e| try hsa_util.check(e),
        }


        self.agents.values()[i] = .{
            .agent_type = agent_type,
            .primary_pool = ctx.primary_pool,
            .shader_engines = shader_engines,
        };
    }
}

const QueryAgentPoolsCtx = struct {
    profiler: *Profiler,
    agent: c.hsa_agent_t,
    primary_pool: c.hsa_amd_memory_pool_t,

    fn cbk(pool: c.hsa_amd_memory_pool_t, data: ?*anyopaque) callconv(.C) c.hsa_status_t {
        const ctx = @ptrCast(*QueryAgentPoolsCtx, @alignCast(@alignOf(QueryAgentPoolsCtx), data.?));

        var segment: c.hsa_amd_segment_t = undefined;
        switch (ctx.profiler.hsa_amd.memory_pool_get_info(
            pool,
            c.HSA_AMD_MEMORY_POOL_INFO_SEGMENT,
            &segment,
        )) {
            c.HSA_STATUS_SUCCESS => {},
            else => |err| return err,
        }

        if (segment != c.HSA_AMD_SEGMENT_GLOBAL)
            return c.HSA_STATUS_SUCCESS;

        var runtime_alloc_allowed: bool = undefined;
        switch (ctx.profiler.hsa_amd.memory_pool_get_info(
            pool,
            c.HSA_AMD_MEMORY_POOL_INFO_RUNTIME_ALLOC_ALLOWED,
            &runtime_alloc_allowed,
        )) {
            c.HSA_STATUS_SUCCESS => {},
            else => |err| return err,
        }
        if (!runtime_alloc_allowed)
            return c.HSA_STATUS_SUCCESS;

        return c.HSA_STATUS_INFO_BREAK;
    }
};

fn queryAgentsCbk(agent: c.hsa_agent_t, data: ?*anyopaque) callconv(.C) c.hsa_status_t {
    const self = @ptrCast(*Profiler, @alignCast(@alignOf(Profiler), data.?));
    _ = self.agents.getOrPut(self.a, agent) catch |err| {
        return hsa_util.toStatus(err);
    };
    return c.HSA_STATUS_SUCCESS;
}

/// Add tracking information for a HSA queue, after it has been created.
pub fn createQueue(
    self: *Profiler,
    agent: c.hsa_agent_t,
    size: u32,
    queue_type: c.hsa_queue_type32_t,
    callback: ?*const fn (c.hsa_status_t, [*c]c.hsa_queue_t, ?*anyopaque) callconv(.C) void,
    data: ?*anyopaque,
    private_segment_size: u32,
    group_segment_size: u32,
) !*c.hsa_queue_t {
    _ = queue_type;
    _ = callback;
    _ = data;
    _ = private_segment_size;
    _ = group_segment_size;

    var backing_queue: [*c]c.hsa_queue_t = undefined;
    try hsa_util.check(self.hsa.queue_create(
        agent,
        size,
        c.HSA_QUEUE_TYPE_MULTI,
        null, // This is what rocprof does. Maybe this needs to be properly converted?
        null, // This is what rocprof does.
        std.math.maxInt(u32), // This is what rocprof does.
        std.math.maxInt(u32), // This is what rocprof does.
        &backing_queue,
    ));
    errdefer _ = self.hsa.queue_destroy(backing_queue);

    // Create our own packet buffer, doorbell, etc.
    var doorbell: c.hsa_signal_t = undefined;
    try hsa_util.check(self.hsa.signal_create(1, 0, null, &doorbell));
    errdefer _ = self.hsa.signal_destroy(doorbell);

    const packet_buf = try self.a.allocWithOptions(c.hsa_packet_t, size, c.hsa_packet_t.alignment, null);
    errdefer self.a.free(packet_buf);

    const pq = try self.a.create(ProfileQueue); // Needs to be pinned in memory.
    pq.* = ProfileQueue{
        .agent = agent,
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
    };

    const result = try self.queues.getOrPut(self.a, doorbell);
    if (result.found_existing) {
        // Should never happen.
        return error.QueueExists;
    }
    result.value_ptr.* = pq;
    return &pq.queue;
}

/// Remove tracking information for a HSA queue, after it has been destroyed.
pub fn destroyQueue(self: *Profiler, queue: *c.hsa_queue_t) !void {
    const pq = self.getProfileQueue(queue) orelse return error.InvalidQueue;
    _ = self.hsa.queue_destroy(pq.backing_queue);
    _ = self.hsa.signal_destroy(pq.queue.doorbell_signal);
    self.a.free(pq.packetBuffer());
    self.a.destroy(pq);
}

/// Submit a generic packet to the backing queue of a ProfileQueue. This function may block until
/// there is enough room for the packet.
pub fn submit(self: *Profiler, pq: *ProfileQueue, packet: *const c.hsa_packet_t) void {
    const queue = pq.backing_queue;
    const write_index = self.hsa.queue_add_write_index_scacq_screl(queue, 1);

    // Busy loop until there is space.
    // TODO: Maybe this can be improved or something?
    while (write_index - self.hsa.queue_load_read_index_relaxed(queue) >= queue.size) {
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
    @atomicStore(u16, &slot.header, packet.header, .Release);

    // Finally, ring the doorbell to notify the agent of the updated packet.
    self.hsa.signal_store_relaxed(queue.doorbell_signal, @intCast(i64, write_index));
}

/// Turn an HSA queue handle into its associated ProfileQueue, if that exists.
pub fn getProfileQueue(self: *Profiler, queue: *const c.hsa_queue_t) ?*ProfileQueue {
    return self.queues.get(queue.doorbell_signal);
}

pub fn startTrace(self: *Profiler, pq: *ProfileQueue) void {
    // The stuff done in this function is mainly based on
    // https://github.com/Mesa3D/mesa/blob/main/src/amd/vulkan/radv_sqtt.c
    // TODO: Find out what we need to bring over. For now, we only target GFX10
    // and the stuff from radv_emit_thread_trace_start.
    std.log.info("starting kernel trace", .{});
    _ = self;
    _ = pq;
}

pub fn stopTrace(self: *Profiler, pq: *ProfileQueue) void {
    std.log.info("stopping kernel trace", .{});
    _ = self;
    _ = pq;
}
