const std = @import("std");
const hsa = @import("hsa.zig");
const Profiler = @import("Profiler.zig");

/// The current log level for profiler log messages.
var log_level: std.log.Level = std.log.default_level;

/// The global profiler instance.
var profiler: Profiler = undefined;

pub fn log(
    comptime level: std.log.Level,
    comptime scope: @TypeOf(.EnumLiteral),
    comptime format: []const u8,
    args: anytype,
) void {
    _ = scope;
    if (@enumToInt(level) > @enumToInt(log_level))
        return;

    const prefix = comptime level.asText();
    std.debug.print("(cycle profiler) " ++ prefix ++ ": " ++ format ++ "\n", args);
}

fn queueCreate(
    agent: hsa.Agent,
    size: u32,
    queue_type: u32,
    callback: ?*const fn (hsa.Status, [*c]hsa.Queue, ?*anyopaque) callconv(.C) void,
    data: ?*anyopaque,
    private_segment_size: u32,
    group_segment_size: u32,
    queue: [*c][*c]hsa.Queue,
) callconv(.C) hsa.Status {
    queue.* = profiler.createQueue(
        agent,
        size,
        @intToEnum(hsa.QueueType32, queue_type),
        callback,
        data,
        private_segment_size,
        group_segment_size,
    ) catch |err| {
        std.log.err("failed to wrap HSA queue: {s}", .{@errorName(err)});
        return hsa.toStatus(err);
    };

    return hsa.c.HSA_STATUS_SUCCESS;
}

fn queueDestroy(queue: [*c]hsa.Queue) callconv(.C) hsa.Status {
    // TODO: Thread safety
    profiler.destroyQueue(queue) catch |err| switch (err) {
        error.InvalidQueue => std.log.err("application tried to destroy an invalid queue", .{}),
    };
    return hsa.c.HSA_STATUS_SUCCESS;
}

fn queueSetProfingEnabled(queue: [*c]hsa.Queue, enable: c_int) callconv(.C) hsa.Status {
    if (profiler.getProfileQueue(queue)) |pq| {
        return profiler.instance.amd_profiling_set_profiler_enabled(pq.backing_queue, enable);
    } else {
        return profiler.instance.amd_profiling_set_profiler_enabled(queue, enable);
    }
}

var submit_nr: usize = 0;

fn signalStore(signal: hsa.Signal, queue_index: hsa.SignalValue) callconv(.C) void {
    const pq = profiler.queues.get(signal) orelse {
        // No such queue, so this is probably a signal for something else.
        profiler.instance.signal_store_relaxed(signal, queue_index);
        return;
    };

    const begin = @atomicRmw(u64, &pq.read_index, .Xchg, @intCast(u64, queue_index + 1), .Monotonic);
    const end = @atomicLoad(u64, &pq.write_index, .Monotonic);

    const packet_buf = pq.packetBuffer();
    var i = begin;
    while (i < end) : (i += 1) {
        const index = i % pq.queue.size;
        const packet = &packet_buf[index];
        if (packet.cast(.kernel_dispatch)) |kernel_dispatch_packet| {
            // TODO: remove hack
            if (submit_nr == 0) {
                profiler.startTrace(pq);
            }
            profiler.dispatchKernel(pq, kernel_dispatch_packet);
            if (submit_nr == 9) {
                profiler.stopTrace(pq) catch |err| {
                    std.log.err("failed to read thread trace: {s}", .{@errorName(err)});
                };
            }
            submit_nr += 1;
        } else {
            profiler.submit(pq, packet);
        }
    }
}

fn executableFreeze(exe: hsa.Executable, options: [*c]const u8) callconv(.C) hsa.Status {
    profiler.registerExecutable(exe) catch |err| {
        std.log.err("failed to register executable: {s}", .{@errorName(err)});
        return hsa.toStatus(err);
    };
    return profiler.instance.executable_freeze(exe, options);
}

fn executableDestroy(exe: hsa.Executable) callconv(.C) hsa.Status {
    profiler.unregisterExecutable(exe);
    return profiler.instance.executable_destroy(exe);
}

fn loadQueueReadIndex(queue: [*c]const hsa.Queue) callconv(.C) u64 {
    if (profiler.getProfileQueue(queue)) |pq| {
        return @atomicLoad(u64, &pq.read_index, .Monotonic);
    } else {
        return profiler.instance.queue_load_read_index_relaxed(queue);
    }
}

fn loadQueueWriteIndex(queue: [*c]const hsa.Queue) callconv(.C) u64 {
    if (profiler.getProfileQueue(queue)) |pq| {
        return @atomicLoad(u64, &pq.write_index, .Monotonic);
    } else {
        return profiler.instance.queue_load_write_index_relaxed(queue);
    }
}

fn storeQueueWriteIndex(queue: [*c]const hsa.Queue, value: u64) callconv(.C) void {
    if (profiler.getProfileQueue(queue)) |pq| {
        @atomicStore(u64, &pq.write_index, value, .Monotonic);
    } else {
        profiler.instance.queue_store_write_index_relaxed(queue, value);
    }
}

fn addQueueWriteIndex(queue: [*c]const hsa.Queue, value: u64) callconv(.C) u64 {
    if (profiler.getProfileQueue(queue)) |pq| {
        return @atomicRmw(u64, &pq.write_index, .Add, value, .Monotonic);
    } else {
        return profiler.instance.queue_add_write_index_relaxed(queue, value);
    }
}

export fn OnLoad(
    table: *hsa.ApiTable,
    runtime_version: u64,
    failed_tool_count: u64,
    failed_tool_names: [*]const [*:0]const u8,
) callconv(.C) bool {
    _ = failed_tool_count;
    _ = failed_tool_names;
    _ = runtime_version;

    if (std.os.getenv("CYCLE_PROFILER_LOG")) |level| {
        log_level = std.meta.stringToEnum(std.log.Level, level) orelse .info;
    }

    std.log.info("loading cycle profiler", .{});
    profiler = Profiler.init(std.heap.c_allocator, table) catch |err| {
        std.log.err("failed to load cycle profiler: {s}", .{@errorName(err)});
        return false;
    };

    // TODO: Override the remaining queue functions, for good measure.

    table.core.queue_create = &queueCreate;
    table.core.queue_destroy = &queueDestroy;
    table.amd_ext.profiling_set_profiler_enabled = &queueSetProfingEnabled;

    table.core.signal_store_relaxed = &signalStore;
    table.core.signal_store_screlease = &signalStore;

    table.core.executable_freeze = &executableFreeze;
    table.core.executable_destroy = &executableDestroy;

    // TODO: Use the proper atomic ordering.
    table.core.queue_load_read_index_relaxed = &loadQueueReadIndex;
    table.core.queue_load_read_index_scacquire = &loadQueueReadIndex;

    table.core.queue_load_write_index_relaxed = &loadQueueWriteIndex;
    table.core.queue_load_write_index_scacquire = &loadQueueWriteIndex;

    table.core.queue_store_write_index_relaxed = &storeQueueWriteIndex;
    table.core.queue_store_write_index_screlease = &storeQueueWriteIndex;

    table.core.queue_add_write_index_scacq_screl = &addQueueWriteIndex;
    table.core.queue_add_write_index_scacquire = &addQueueWriteIndex;
    table.core.queue_add_write_index_relaxed = &addQueueWriteIndex;
    table.core.queue_add_write_index_screlease = &addQueueWriteIndex;

    return true;
}

export fn OnUnload() callconv(.C) void {
    std.log.info("shutting down", .{});
    profiler.save("dump") catch |err| {
        std.log.err("failed to save trace: {s}", .{@errorName(err)});
    };
    profiler.deinit();
}

/// HSA does not call OnUnload() properly, so we just hack it in using the shared library destructor.
// TODO: Make sure that the profiler is not created/destroyed twice?
export const fini linksection(".fini_array") = &OnUnload;
