const Profiler = @This();

const std = @import("std");
const elf = @import("elf.zig");
const hsa = @import("hsa.zig");
const rgp = @import("rgp.zig");
const pm4 = @import("pm4.zig");
const sqtt = @import("sqtt.zig");
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
            return @enumToInt(self) >> 8;
        }

        pub fn minor(self: GcnArch) u32 {
            return (@enumToInt(self) >> 4) & 0xF;
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

/// Meta-information associated with a kernel.
pub const KernelInfo = struct {
    /// Name of the kernel descriptor symbol. Allocation is owned.
    /// This name is of form <name>.kd, so to get the neat name the
    /// suffix must be stripped.
    descriptor_name: []const u8,

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
/// TODO: we can get rid of the duplicate signal handle by using a context.
queues: std.AutoArrayHashMapUnmanaged(hsa.Signal, *ProfileQueue) = .{},
/// A map of loaded kernels, indexed by kernel code handle.
kernels: std.AutoArrayHashMapUnmanaged(u64, KernelInfo) = .{},
/// A list of tracing sessions. Currently, we just have one
/// global session for every agent. This array list is indexed
/// by the same index that the agent has in `agents`.
sessions: std.ArrayListUnmanaged(Session) = .{},
/// Code object load events. These are common for all agents, and are regardless of session.
load_events: std.ArrayListUnmanaged(rgp.Capture.LoadEvent) = .{},
/// The actual code objects that were encountered. The binary is owned by self.a.
// TODO: Is this per-agent?
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
    for (self.queues.values()) |pq| {
        pq.thread_trace.deinit(&self.instance);
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

    self.cpu_agent = for (self.agents.keys()) |info, i| {
        if (info.properties.agent_type == .cpu)
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
        .primary_pool = undefined,
        .properties = undefined,
    }) catch return error.OutOfResources;
    std.debug.assert(!result.found_existing); // bug in HSA: the same agent is reported twice.
    const info = result.key_ptr;

    info.properties = .{
        .name = self.instance.getAgentInfo(agent, .name),
        .agent_type = self.instance.getAgentInfo(agent, .device_type),
        .shader_engines = 4, // self.instance.getAgentInfo(agent, .num_shader_engines),
        .vendor_name = self.instance.getAgentInfo(agent, .vendor_name),
        .product_name = self.instance.getAgentInfo(agent, .product_name),
        .compute_units = 72, // self.instance.getAgentInfo(agent, .num_compute_units),
        .simds_per_cu = 4, // self.instance.getAgentInfo(agent, .num_simds_per_cu),
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
        const gcn_arch = if (std.mem.startsWith(u8, name, "gfx")) blk: {
            // Try to parse the remainder as gfx architecture level. These are in the form
            // `gfxX` where X are 3 or 4 hexadecimal chars. We're just going to cheat and
            // interpret the rest of the string as hex.
            if (std.fmt.parseInt(u32, name[3..], 16)) |arch_level| {
                break :blk @intToEnum(AgentInfo.GcnArch, arch_level);
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

/// Submit a PM4 command buffer to an HSA queue.
pub fn submitPm4(
    self: *Profiler,
    pq: *ProfileQueue,
    commands: []const pm4.Word,
    completion_signal: ?hsa.Signal,
) void {
    var packet = hsa.Pm4IndirectBufferPacket.init(commands);
    if (completion_signal) |signal| {
        packet.completion_signal = signal;
    }
    self.submit(pq, packet.asHsaPacket());
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

    self.submitPm4(pq, pq.thread_trace.start_commands, null);
}

/// Stop tracing.
pub fn stopTrace(self: *Profiler, pq: *ProfileQueue) !void {
    std.log.info("stopping kernel trace", .{});
    const signal = pq.thread_trace.completion_signal;
    self.submitPm4(pq, pq.thread_trace.stop_commands, signal);

    // Wait until the stop trace packet has been processed.
    // TODO: Do we need this? we're going to wait until the GPU is idle during the read anyway...
    while (true) {
        const value = self.instance.signalWait(
            signal,
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
    self.instance.signalStore(signal, 1, .Monotonic);

    // const cpu_agent_info = self.agents.keys()[self.cpu_agent];
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
    // Obtain the AMD kernel code handle for this packet.
    // TODO: Make sure that this is a device queue?
    const kernel_code = self.instance.loaderQueryHostAddress(
        hsa.AmdKernelCode,
        @intToPtr(*const hsa.AmdKernelCode, packet.kernel_object),
    );
    _ = kernel_code;
    // std.log.debug("{}", .{kernel_code});

    // There is no real pipeline bind moment in hsa so we will just use the dispatch moment

    self.submit(pq, @ptrCast(*align(hsa.Packet.alignment) const hsa.Packet, packet));
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
            std.mem.copy(u8, binary, ptr[0..len]);
            break :blk binary;
        },
        else => {
            std.log.warn("cannot load code object '{s}'", .{uri});
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

    // Quickly compute a hash from the elf file.
    const hash = std.hash.Wyhash.hash(0, binary);
    std.log.debug("registering executable '{s}' with hash 0x{x:0>16}", .{ uri, hash });

    try self.load_events.append(self.a, .{
        .event_type = .load_to_gpu_memory,
        .base_address = text_va +% @bitCast(u64, load_delta),
        .code_object_hash = hash,
        .timestamp = @bitCast(u64, @truncate(i64, std.time.nanoTimestamp())),
    });

    // std.log.debug(".text va: 0x{X}, delta: 0x{X}, loaded .text va: 0x{X}", .{text_va, load_delta, real_text_va});

    _ = try self.instance.iterateSymbols(exe, self, registerExecutableSymbolsCbk);
}

fn registerExecutableCodeObjectCbk(self: *Profiler, exe: hsa.Executable, co: hsa.LoadedCodeObject) !?hsa.LoadedCodeObject {
    // ROCclr always registers only a single code object, so it seems
    // find to just return the one binary.
    _ = exe;
    _ = self;
    return co;
}

fn registerExecutableSymbolsCbk(self: *Profiler, exe: hsa.Executable, sym: hsa.Symbol) !?void {
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
    };

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
// TODO: Make cycle profiler have consistent GPU indices, and only profile specified
// GPUs or something.
pub fn save(self: *Profiler, basename: []const u8) !void {
    const cpu_agent_info = self.agents.keys()[self.cpu_agent];

    for (self.sessions.items) |session, agent_index| {
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
