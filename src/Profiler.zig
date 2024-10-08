const Profiler = @This();

const std = @import("std");
const elf = @import("elf.zig");
const hsa = @import("hsa.zig");
const rgp = @import("rgp.zig");
const pm4 = @import("pm4.zig");
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

    /// Get a handle to the packet buffer of this profile queue.
    pub fn packetBuffer(self: *ProfileQueue) []align(hsa.Packet.alignment) hsa.Packet {
        return hsa.queuePacketBuffer(&self.queue);
    }

    pub const HashContext = struct {
        pub fn hash(self: @This(), pq: *ProfileQueue) u32 {
            _ = self;
            return @truncate(std.hash.Wyhash.hash(0, std.mem.asBytes(&pq.queue.doorbell_signal.handle)));
        }

        pub fn eql(self: @This(), a: *ProfileQueue, b: *ProfileQueue, b_index: usize) bool {
            _ = self;
            _ = b_index;
            return a.queue.doorbell_signal.handle == b.queue.doorbell_signal.handle;
        }
    };

    pub const HashContextByDoorbell = struct {
        pub fn hash(self: @This(), doorbell: hsa.Signal) u32 {
            _ = self;
            return @truncate(std.hash.Wyhash.hash(0, std.mem.asBytes(&doorbell.handle)));
        }

        pub fn eql(self: @This(), doorbell: hsa.Signal, pq: *ProfileQueue, b_index: usize) bool {
            _ = self;
            _ = b_index;
            return doorbell.handle == pq.queue.doorbell_signal.handle;
        }
    };
};

/// Meta-information tho avoid having it to query all the time.
/// This structure also contains information that we need to know when writing the RGP trace,
/// because that may happen at a moment that HSA is no longer initialized.
pub const AgentInfo = struct {
    /// The AMD architecture level. This value is the architecture in hexadecimal (eg, 0x1030 for gfx1030).
    /// If this is not applicable for the current agent, its .not_applicable.
    pub const GcnArch = enum(u32) {
        /// The device did not report a valid GCN arch.
        invalid = 0,
        // Common ones can be added here, for utility.
        gfx1030 = 0x1030,
        _,

        pub fn major(self: GcnArch) u32 {
            return @intFromEnum(self) >> 8;
        }

        pub fn minor(self: GcnArch) u32 {
            return (@intFromEnum(self) >> 4) & 0xF;
        }
    };

    /// Properties that are only valid for GPU agents.
    pub const GpuProperties = struct {
        gcn_arch: GcnArch,
        memory_freq: u32,
        memory_width: u32,
    };

    /// Agent properties that are required when dumping the RGP capture,
    /// as we cannot be sure that the agent is still alive by then.
    /// Note: this struct can also contain information from HSA_AMD_AGENT_INFO
    /// queries. Sometimes those just return an equivalent property, but when they
    /// crash, they should be added to `GpuProperties`.
    pub const Properties = struct {
        name: [64]u8,
        agent_type: hsa.DeviceType,
        shader_engines: u32,
        vendor_name: [64]u8,
        product_name: [64]u8,
        compute_units: u32,
        simds_per_cu: u32,
        cache_size: [4]u32,
        clock_freq: u32,
        timestamp_freq: u64,
        chip_id: u32,
        asic_revision: u32,
        gpu_properties: ?GpuProperties,
    };

    /// The agent that this information concerns. Will be used as key for the `agents` map.
    agent: hsa.Agent,
    /// The primary (device-local) pool to allocate memory from for this agent.
    primary_pool: hsa.MemoryPool,
    /// Agent properties
    properties: Properties,

    pub const HashContext = struct {
        pub fn hash(self: @This(), agent_info: AgentInfo) u32 {
            _ = self;
            return @truncate(std.hash.Wyhash.hash(0, std.mem.asBytes(&agent_info.agent.handle)));
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
            return @truncate(std.hash.Wyhash.hash(0, std.mem.asBytes(&agent.handle)));
        }

        pub fn eql(self: @This(), agent: hsa.Agent, agent_info: AgentInfo, b_index: usize) bool {
            _ = self;
            _ = b_index;
            return agent.handle == agent_info.agent.handle;
        }
    };
};

/// Meta-information associated with a kernel.
pub const KernelInfo = struct {
    /// Name of the kernel descriptor symbol. Allocation is owned.
    /// This name is of form <name>.kd, so to get the neat name the
    /// suffix must be stripped.
    descriptor_name: []const u8,
    /// The hash of the code object that this kernel belongs to.
    code_object_hash: u64,

    /// Get the proper kernel name, without the descriptor suffix.
    fn name(self: KernelInfo) []const u8 {
        return self.descriptor_name[0 .. self.descriptor_name.len - 3];
    }
};

/// This structure models an agent's complete tracing session,
/// along with sqtt traces, events, etc.
pub const Session = struct {
    traces: std.ArrayListUnmanaged(ThreadTrace.Trace) = .{},
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
queues: std.ArrayHashMapUnmanaged(*ProfileQueue, void, ProfileQueue.HashContext, true) = .{},
/// A map of loaded kernels, indexed by kernel code handle.
kernels: std.AutoArrayHashMapUnmanaged(u64, KernelInfo) = .{},
/// A list of tracing sessions. Currently, we just have one
/// global session for every agent. This array list is indexed
/// by the same index that the agent has in `agents`.
sessions: std.ArrayListUnmanaged(Session) = .{},
/// Code object load events. These are common for all agents, and are regardless of session.
load_events: std.ArrayListUnmanaged(rgp.Capture.LoadEvent) = .{},
/// The actual code objects that were encountered. The binary is owned by self.a.
code_objects: std.ArrayListUnmanaged(rgp.Capture.CodeObject) = .{},

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
    for (self.queues.keys()) |pq| {
        pq.thread_trace.deinit(&self.instance);
        self.a.destroy(pq);
    }

    for (self.kernels.values()) |info| {
        self.a.free(info.descriptor_name);
    }

    for (self.sessions.items) |*session| {
        for (session.traces.items) |*trace| {
            trace.deinit(self.a);
        }
        session.traces.deinit(self.a);
    }

    for (self.code_objects.items) |code_object| {
        self.a.free(code_object.elf_binary);
    }

    self.agents.deinit(self.a);
    self.queues.deinit(self.a);
    self.kernels.deinit(self.a);
    self.sessions.deinit(self.a);
    self.load_events.deinit(self.a);
    self.code_objects.deinit(self.a);
    self.* = undefined;
}

fn queryAgents(self: *Profiler) !void {
    _ = try self.instance.iterateAgents(self, queryAgentsCbk);

    // Make sure that the sessions array always has the same size as the agents
    // list.
    if (self.sessions.items.len < self.agents.count()) {
        const prev_len = self.sessions.items.len;
        try self.sessions.resize(self.a, self.agents.count());
        for (self.sessions.items[prev_len..]) |*session| session.* = .{};
    }

    self.cpu_agent = for (self.agents.keys(), 0..) |info, i| {
        if (info.properties.agent_type == .cpu)
            break @intCast(i);
    } else {
        std.log.err("system has no cpu agent", .{});
        return error.Generic;
    };
}

fn queryAgentsCbk(self: *Profiler, agent: hsa.Agent) !?void {
    const result = self.agents.getOrPut(self.a, AgentInfo{
        .agent = agent,
        // Fields are filled in momentarily.
        .primary_pool = undefined,
        .properties = undefined,
    }) catch return error.OutOfResources;
    std.debug.assert(!result.found_existing); // bug in HSA: the same agent is reported twice.
    const info = result.key_ptr;

    info.properties = .{
        .name = self.instance.getAgentInfo(agent, .name),
        .agent_type = self.instance.getAgentInfo(agent, .device_type),
        .shader_engines = self.instance.getAgentInfo(agent, .num_shader_engines),
        .vendor_name = self.instance.getAgentInfo(agent, .vendor_name),
        .product_name = self.instance.getAgentInfo(agent, .product_name),
        .compute_units = self.instance.getAgentInfo(agent, .num_compute_units),
        .simds_per_cu = self.instance.getAgentInfo(agent, .num_simds_per_cu),
        .cache_size = self.instance.getAgentInfo(agent, .cache_size),
        .clock_freq = self.instance.getAgentInfo(agent, .max_clock_freq),
        .chip_id = self.instance.getAgentInfo(agent, .chip_id),
        .asic_revision = self.instance.getAgentInfo(agent, .asic_revision),
        .timestamp_freq = self.instance.getAgentInfo(agent, .timestamp_freq),
        .gpu_properties = null,
    };

    const name = std.mem.sliceTo(&info.properties.name, 0);
    const type_str = switch (info.properties.agent_type) {
        .cpu => "cpu",
        .gpu => "gpu",
        _ => "other",
    };
    std.log.info("found device '{s}' of type {s}", .{ name, type_str });

    if (info.properties.agent_type == .gpu) {
        const gcn_arch: AgentInfo.GcnArch = if (std.mem.startsWith(u8, name, "gfx")) blk: {
            // Try to parse the remainder as gfx architecture level. These are in the form
            // `gfxX` where X are 3 or 4 hexadecimal chars. We're just going to cheat and
            // interpret the rest of the string as hex.
            if (std.fmt.parseInt(u32, name[3..], 16)) |arch_level| {
                break :blk @enumFromInt(arch_level);
            } else |_| {
                std.log.err("could not parse gfx-like device name '{s}' as gcn arch level", .{name});
                break :blk .invalid;
            }
        } else blk: {
            std.log.err("GPU device does not have gfx-like device name (its '{s}'), could not determine gcn level", .{name});
            break :blk .invalid;
        };

        info.properties.gpu_properties = .{
            .gcn_arch = gcn_arch,
            .memory_freq = self.instance.getAgentInfo(agent, .max_memory_freq),
            .memory_width = self.instance.getAgentInfo(agent, .memory_width),
        };
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

    std.debug.assert(try self.queues.fetchPut(self.a, pq, {}) == null);

    // Always enable HSA profiling on the backing queue. Note: ROCR will also set this on the queue, but since
    // this is implementing a custom queue, that will not enable it here.
    self.instance.setProfilerEnabled(pq.backing_queue, true);

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
    std.debug.assert(self.queues.swapRemoveAdapted(queue.doorbell_signal, ProfileQueue.HashContextByDoorbell{}));
}

/// Submit a generic packet to the backing queue of a ProfileQueue. This function may block until
/// there is enough room for the packet.
pub fn submit(self: *Profiler, pq: *ProfileQueue, packet: *const hsa.Packet) void {
    self.instance.submit(pq.backing_queue, packet);
}

/// Turn an HSA queue handle into its associated ProfileQueue, if that exists.
pub fn getProfileQueue(self: *Profiler, queue: *const hsa.Queue) ?*ProfileQueue {
    return self.getProfileQueueByDoorbell(queue.doorbell_signal);
}

/// Get a profile queue that corresponds to a particular doorbell
pub fn getProfileQueueByDoorbell(self: *Profiler, doorbell: hsa.Signal) ?*ProfileQueue {
    return self.queues.getKeyAdapted(doorbell, ProfileQueue.HashContextByDoorbell{});
}

/// Utility command to wait on a signal binary and reset it immediately.
pub fn signalWaitAndReset(self: *Profiler, signal: hsa.Signal) void {
    while (true) {
        // TODO: Really check the timeout and stuff.
        const value = self.instance.signalWait(
            signal,
            .lt,
            1,
            stop_trace_signal_timeout_ns,
            .blocked,
            .acquire,
        );
        switch (value) {
            0 => break,
            1 => {},
            else => unreachable, // Not a binary signal.
        }
    }
    self.instance.signalStore(signal, 1, .monotonic);
}

/// Start tracing.
pub fn startTrace(self: *Profiler, pq: *ProfileQueue) void {
    // The stuff done in this function is mainly based on
    // https://github.com/Mesa3D/mesa/blob/main/src/amd/vulkan/radv_sqtt.c
    // TODO: Find out what we need to bring over. For now, we only target GFX10
    // and the stuff from radv_emit_thread_trace_start.
    std.log.info("starting trace", .{});
    self.submit(pq, pq.thread_trace.start_packet.asHsaPacket());
    pq.thread_trace.cmd_id = 0; // TODO: move this entire function to ThreadTrace.
}

/// Stop tracing.
pub fn stopTrace(self: *Profiler, pq: *ProfileQueue) !void {
    std.log.info("stopping trace", .{});

    self.submit(pq, pq.thread_trace.stop_packet.asHsaPacket());
    self.signalWaitAndReset(pq.thread_trace.stop_packet.completion_signal);

    const gpu_agent_info = self.agents.keys()[pq.agent];
    const traces = try pq.thread_trace.read(self.a, gpu_agent_info);
    defer self.a.free(traces); // Note: only the array must be freed, traces are moved.

    const session = &self.sessions.items[pq.agent];
    session.traces.appendSlice(self.a, traces) catch |err| {
        for (traces) |*trace| trace.deinit(self.a);
        return err;
    };
}

/// Dispatch a kernel packet. This function makes sure to record the relevant info in the queue's trace.
pub fn dispatchKernel(
    self: *Profiler,
    pq: *ProfileQueue,
    packet: *align(hsa.Packet.alignment) const hsa.KernelDispatchPacket,
) void {
    // Fetch kernel meta-information for this packet.
    const kernel_info = self.kernels.get(packet.kernel_object) orelse {
        std.log.err("kernel object 0x{x:0>16} was not registered, cannot trace", .{packet.kernel_object});
        unreachable; // TODO: gracefully handle.
    };

    std.log.debug("launching kernel '{s}' with workgroup size {{{}, {}, {}}} and work size {{{}, {}, {}}}", .{
        kernel_info.name(),
        packet.workgroup_size_x,
        packet.workgroup_size_y,
        packet.workgroup_size_z,
        packet.grid_size_x / packet.workgroup_size_x,
        packet.grid_size_y / packet.workgroup_size_y,
        packet.grid_size_z / packet.workgroup_size_z,
    });

    const update_packet = pq.thread_trace.update(
        kernel_info.name(),
        kernel_info.code_object_hash,
        packet.grid_size_x / packet.workgroup_size_x,
        packet.grid_size_y / packet.workgroup_size_y,
        packet.grid_size_z / packet.workgroup_size_z,
    );

    var dispatch_packet align(hsa.Packet.alignment) = packet.*;
    // Need this signal to be here so that we can get the dispatch time.
    // Note: It looks like the ROCR-Runtime does not set this field, ever, and instead measures dispatch
    // time another way.
    // TODO: Check that, because if they do, measuring this may become really annoying.
    // TODO: Handle any existing signals in a more graceful/efficient manner anyway.
    // TODO: Create a separate signal for this instead of stealing this one.
    const signal = pq.thread_trace.stop_packet.completion_signal;
    dispatch_packet.completion_signal = signal;

    self.submit(pq, update_packet.asHsaPacket());
    self.submit(pq, @ptrCast(&dispatch_packet));
    self.signalWaitAndReset(signal);

    const agent = self.agents.keys()[pq.agent].agent;
    const dispatch_time = self.instance.getDispatchTime(agent, signal);

    const freq = self.agents.keys()[pq.agent].properties.timestamp_freq;
    const time = @as(f64, @floatFromInt(dispatch_time.end -% dispatch_time.start)) * (1e3 / @as(f64, @floatFromInt(freq)));

    std.log.debug("kernel dispatch time: {} {}", .{ dispatch_time.start, dispatch_time.end });
    std.log.debug(".. elapsed: {d} ms", .{time});
}

/// Track meta-information about an HSA executable. Should be called when
/// the executable is frozen.
pub fn registerExecutable(self: *Profiler, exe: hsa.Executable) !void {
    const code_object = (try self.instance.iterateLoadedCodeObjects(exe, self, registerExecutableCodeObjectCbk)) orelse {
        std.log.err("executable 0x{x} has no code object", .{exe.handle});
        return;
    };

    const uri = try self.instance.getLoadedCodeObjectUri(code_object, self.a);
    defer self.a.free(uri);

    const storage_type = self.instance.getLoadedCodeObjectInfo(code_object, .storage_type);
    const binary = switch (storage_type) {
        .memory => blk: {
            const ptr = self.instance.getLoadedCodeObjectInfo(code_object, .memory_base);
            const len = self.instance.getLoadedCodeObjectInfo(code_object, .memory_size);
            const binary = try self.a.alignedAlloc(u8, elf.alignment, len);
            @memcpy(binary, ptr[0..len]);
            break :blk binary;
        },
        else => {
            std.log.warn("cannot load code object for executable '{s}'", .{uri});
            return error.Generic;
        },
    };
    self.code_objects.append(self.a, .{
        .elf_binary = binary,
    }) catch |err| {
        self.a.free(binary); // Manually destroy on error to avoid double free.
        return err;
    };

    const text_va = elf.getSectionVirtualAddr(binary, ".text") catch return error.Generic;
    const load_delta = self.instance.getLoadedCodeObjectInfo(code_object, .load_delta);

    const hash = std.hash.Wyhash.hash(0, binary);

    std.log.debug("registering executable '{s}' with hash 0x{x:0>16}", .{ uri, hash });

    try self.load_events.append(self.a, .{
        .event_type = .load_to_gpu_memory,
        .base_address = text_va +% @as(u64, @bitCast(load_delta)),
        .code_object_hash = hash,
        .timestamp = @as(u64, @intCast(std.time.nanoTimestamp())),
    });

    var ctx = RegisterExecutableSymbolsCtx{
        .profiler = self,
        .code_object_hash = hash,
    };
    _ = try self.instance.iterateSymbols(exe, &ctx, registerExecutableSymbolsCbk);
}

fn registerExecutableCodeObjectCbk(self: *Profiler, exe: hsa.Executable, co: hsa.LoadedCodeObject) !?hsa.LoadedCodeObject {
    // ROCclr always registers only a single code object, so it seems
    // find to just return the one binary.
    _ = exe;
    _ = self;
    return co;
}

const RegisterExecutableSymbolsCtx = struct {
    profiler: *Profiler,
    code_object_hash: u64,
};

fn registerExecutableSymbolsCbk(ctx: *RegisterExecutableSymbolsCtx, exe: hsa.Executable, sym: hsa.Symbol) !?void {
    const self = ctx.profiler;
    _ = exe;
    const kind = self.instance.getSymbolInfo(sym, .kind);
    if (kind != .kernel)
        return null; // We don't care about non-kernels.

    const kernel_object = self.instance.getSymbolInfo(sym, .kernel_object);
    const result = try self.kernels.getOrPut(self.a, kernel_object);
    if (result.found_existing)
        return null; // Avoid re-registering.

    const name = try self.instance.getSymbolName(sym, self.a);
    errdefer self.a.free(name);

    std.debug.assert(std.mem.endsWith(u8, name, ".kd")); // Malformed kernel symbol name.

    result.value_ptr.* = .{
        .descriptor_name = name,
        .code_object_hash = ctx.code_object_hash,
    };
    std.log.debug("executable with kernel name '{s}' and kernel object 0x{x:0>16}", .{ result.value_ptr.name(), kernel_object });

    return null;
}

/// Un-track meta-information about an HSA executable. Should be called when the executable
/// is destroyed.
pub fn unregisterExecutable(self: *Profiler, exe: hsa.Executable) void {
    _ = self;
    _ = exe;
}

/// Save the current profiling information as an RGP trace.
/// `basename` is the capture's basename. It will be saved as `basename-<gpu-index>.rgp`.
/// `gpu-index` does NOT correlate to anything.
// TODO: Make goniometer have consistent GPU indices, and only profile specified
// GPUs or something.
pub fn save(self: *Profiler, basename: []const u8) !void {
    const cpu_agent_info = self.agents.keys()[self.cpu_agent];

    for (self.sessions.items, 0..) |session, agent_index| {
        const gpu_agent_info = self.agents.keys()[agent_index];
        if (gpu_agent_info.properties.agent_type != .gpu)
            continue; // TODO: Can RGP trace CPU stuff? I doubt it, plus who uses HSA for CPUs anyway.
        if (session.traces.items.len == 0)
            continue; // No point in dumping an empty trace.

        const capture = rgp.Capture{
            .cpu_agent = &cpu_agent_info,
            .gpu_agent = &gpu_agent_info,
            .traces = session.traces.items,
            .load_events = self.load_events.items,
            .code_objects = self.code_objects.items,
        };

        const filename = try std.fmt.allocPrint(self.a, "{s}-{}.rgp", .{ basename, agent_index });
        defer self.a.free(filename);
        try capture.dump(filename);
        std.log.info("saved capture to '{s}'", .{filename});
    }
}
