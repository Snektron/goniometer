const Profiler = @This();

const std = @import("std");
const c = @import("c.zig");

/// Information that is tracket per queue.
pub const QueueInfo = struct {
    /// The corresponding HSA queue handle.
    queue: *c.hsa_queue_t,
    /// The last write index of the queue.
    last_index: usize,
};

/// The allocator to use for profiling data.
a: std.mem.Allocator,

/// The api table that we can use to invoke HSA functions.
/// Only the core table is relevant, we don't need the extension functions.
hsa_core: c.CoreApiTable,

/// The CPU agent that we use to allocate host resources, such as CPU-GPU
/// shared memory etc.
cpu_agent: c.hsa_agent_t,

/// Dynamically loaded libhsa-amd-aqlprofile.
aqlprofile: struct {
    lib: std.DynLib,
    start: *const @TypeOf(c.hsa_ven_amd_aqlprofile_start),
},

/// A map of queue handles to queue state. A queue is identified by its doorbell signal.
queues: std.AutoArrayHashMapUnmanaged(c.hsa_signal_t, QueueInfo) = .{},

pub fn init(a: std.mem.Allocator, hsa_fns: *c.ApiTable) !Profiler {
    var self = Profiler{
        .a = a,
        .hsa_core = hsa_fns.core.*,
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
        "hsa_ven_amd_aqlprofile_start"
    ) orelse return error.AqlProfileMissingLibraryFunction;

    try self.queryAgents();

    return self;
}

pub fn deinit(self: *Profiler) void {
    self.aqlprofile.lib.close();
    self.* = undefined;
}

fn queryAgents(self: *Profiler) !void {
    const status = self.hsa_core.hsa_iterate_agents_fn(&queryAgentsCbk, self);
    if (status != c.HSA_STATUS_SUCCESS) {
        return error.HsaError;
    }
}

fn queryAgentsCbk(agent: c.hsa_agent_t, data: ?*anyopaque) callconv(.C) c.hsa_status_t {
    const profiler = @ptrCast(*Profiler, @alignCast(@alignOf(Profiler), data.?));

    var name_buf: [64]u8 = undefined;
    const name_status = profiler.hsa_core.hsa_agent_get_info_fn(agent, c.HSA_AGENT_INFO_NAME, &name_buf);
    if (name_status != c.HSA_STATUS_SUCCESS) {
        return name_status;
    }
    const name = std.mem.sliceTo(&name_buf, 0);

    var agent_type: c.hsa_device_type_t = undefined;
    const type_status = profiler.hsa_core.hsa_agent_get_info_fn(agent, c.HSA_AGENT_INFO_DEVICE, &agent_type);
    if (type_status != c.HSA_STATUS_SUCCESS) {
        return type_status;
    }

    const type_str = switch (agent_type) {
        c.HSA_DEVICE_TYPE_CPU => "cpu",
        c.HSA_DEVICE_TYPE_GPU => "gpu",
        else => "other",
    };

    std.log.info("system has agent '{s}' of type {s}", .{name, type_str});

    if (agent_type == c.HSA_DEVICE_TYPE_CPU) {
        // Just use the last cpu that we found as the cpu agent to use for allocation and such.
        profiler.cpu_agent = agent;
    }

    return c.HSA_STATUS_SUCCESS;
}

/// Add tracking information for a HSA queue, after it has been created.
pub fn createQueue(self: *Profiler, queue: *c.hsa_queue_t) !void {
    const result = try self.queues.getOrPut(self.a, queue.doorbell_signal);
    if (result.found_existing) {
        // Should never happen.
        return error.QueueExists;
    }

    result.value_ptr.* = .{
        .queue = queue,
        .last_index = 0,
    };
}

/// Remove tracking information for a HSA queue, after it has been destroyed.
pub fn destroyQueue(self: *Profiler, queue: *c.hsa_queue_t) !void {
    const ok = self.queues.swapRemove(queue.doorbell_signal);
    if (!ok)
        return error.InvalidQueue;
}
