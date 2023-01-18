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
    std.debug.print("(goniometer) " ++ prefix ++ ": " ++ format ++ "\n", args);
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

fn queueDestroy(queue: [*c]hsa.Queue) callconv(.C) hsa.Status {
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

fn queue_intercept(comptime order: std.builtin.AtomicOrder) type {
    return struct {
        fn signalStore(signal: hsa.Signal, queue_index: hsa.SignalValue) callconv(.C) void {
            const pq = profiler.getProfileQueueByDoorbell(signal) orelse {
                // No such queue, so this is probably a signal for something else.
                profiler.instance.signalStore(signal, queue_index, order);
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
                    profiler.startTrace(pq);
                    profiler.dispatchKernel(pq, kernel_dispatch_packet);
                    profiler.stopTrace(pq) catch |err| {
                        std.log.err("failed to read thread trace: {s}", .{@errorName(err)});
                    };
                } else {
                    profiler.submit(pq, packet);
                }
            }
        }

        fn loadQueueReadIndex(queue: [*c]const hsa.Queue) callconv(.C) u64 {
            if (profiler.getProfileQueue(queue)) |pq| {
                return @atomicLoad(u64, &pq.read_index, order);
            } else {
                return profiler.instance.queueLoadReadIndex(queue, order);
            }
        }

        fn loadQueueWriteIndex(queue: [*c]const hsa.Queue) callconv(.C) u64 {
            if (profiler.getProfileQueue(queue)) |pq| {
                return @atomicLoad(u64, &pq.write_index, order);
            } else {
                return profiler.instance.queueLoadWriteIndex(queue, order);
            }
        }

        fn storeQueueWriteIndex(queue: [*c]const hsa.Queue, value: u64) callconv(.C) void {
            if (profiler.getProfileQueue(queue)) |pq| {
                @atomicStore(u64, &pq.write_index, value, order);
            } else {
                profiler.instance.queueStoreWriteIndex(queue, value, order);
            }
        }

        fn addQueueWriteIndex(queue: [*c]const hsa.Queue, value: u64) callconv(.C) u64 {
            if (profiler.getProfileQueue(queue)) |pq| {
                return @atomicRmw(u64, &pq.write_index, .Add, value, order);
            } else {
                return profiler.instance.queueAddWriteIndex(queue, value, order);
            }
        }
    };
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

    if (std.os.getenv("GONIOMETER_LOG")) |level| {
        log_level = std.meta.stringToEnum(std.log.Level, level) orelse .info;
    }

    std.log.info("loading goniometer", .{});
    profiler = Profiler.init(std.heap.c_allocator, table) catch |err| {
        std.log.err("failed to load goniometer: {s}", .{@errorName(err)});
        return false;
    };

    // TODO: Override the remaining queue functions, for good measure.

    table.core.queue_create = &queueCreate;
    table.core.queue_destroy = &queueDestroy;
    table.amd_ext.profiling_set_profiler_enabled = &queueSetProfingEnabled;

    table.core.signal_store_relaxed = &queue_intercept(.Monotonic).signalStore;
    table.core.signal_store_screlease = &queue_intercept(.Release).signalStore;

    table.core.queue_load_read_index_relaxed = &queue_intercept(.Monotonic).loadQueueReadIndex;
    table.core.queue_load_read_index_scacquire = &queue_intercept(.Acquire).loadQueueReadIndex;

    table.core.queue_load_write_index_relaxed = &queue_intercept(.Monotonic).loadQueueWriteIndex;
    table.core.queue_load_write_index_scacquire = &queue_intercept(.Acquire).loadQueueWriteIndex;

    table.core.queue_store_write_index_relaxed = &queue_intercept(.Monotonic).storeQueueWriteIndex;
    table.core.queue_store_write_index_screlease = &queue_intercept(.Release).storeQueueWriteIndex;

    table.core.queue_add_write_index_relaxed = &queue_intercept(.Monotonic).addQueueWriteIndex;
    table.core.queue_add_write_index_scacq_screl = &queue_intercept(.AcqRel).addQueueWriteIndex;
    table.core.queue_add_write_index_scacquire = &queue_intercept(.Acquire).addQueueWriteIndex;
    table.core.queue_add_write_index_screlease = &queue_intercept(.Release).addQueueWriteIndex;

    table.core.executable_freeze = &executableFreeze;
    table.core.executable_destroy = &executableDestroy;

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
