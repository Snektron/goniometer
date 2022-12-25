const std = @import("std");
const c = @import("c.zig");
const hsa_util = @import("hsa_util.zig");
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
    agent: c.hsa_agent_t,
    size: u32,
    queue_type: c.hsa_queue_type32_t,
    callback: ?*const fn (c.hsa_status_t, [*c]c.hsa_queue_t, ?*anyopaque) callconv(.C) void,
    data: ?*anyopaque,
    private_segment_size: u32,
    group_segment_size: u32,
    queue: [*c][*c]c.hsa_queue_t,
) callconv(.C) c.hsa_status_t {
    queue.* = profiler.createQueue(
        agent,
        size,
        queue_type,
        callback,
        data,
        private_segment_size,
        group_segment_size,
    ) catch |err| {
        std.log.err("failed to wrap HSA queue: {s}", .{@errorName(err)});
        return hsa_util.toStatus(err);
    };

    return c.HSA_STATUS_SUCCESS;
}

fn queueDestroy(queue: [*c]c.hsa_queue_t) callconv(.C) c.hsa_status_t {
    // TODO: Thread safety
    profiler.destroyQueue(queue) catch |err| switch (err) {
        error.InvalidQueue => std.log.err("application tried to destroy an invalid queue", .{}),
    };
    return c.HSA_STATUS_SUCCESS;
}

fn signalStore(signal: c.hsa_signal_t, queue_index: c.hsa_signal_value_t) callconv(.C) void {
    const pq = profiler.queues.get(signal) orelse {
        // No such queue, so this is probably a signal for something else.
        profiler.hsa.signal_store_relaxed(signal, queue_index);
        return;
    };

    const begin = @atomicRmw(u64, &pq.read_index, .Xchg, @intCast(u64, queue_index + 1), .Monotonic);
    const end = @atomicLoad(u64, &pq.write_index, .Monotonic);

    const packet_buf = pq.packetBuffer();
    var i = begin;
    while (i < end) : (i += 1) {
        const index = i % pq.queue.size;
        const packet = &packet_buf[index];
        if (packet.packetType() == c.HSA_PACKET_TYPE_KERNEL_DISPATCH) {
            profiler.startTrace(pq);
            profiler.submit(pq, packet);
            profiler.stopTrace(pq);
        } else {
            profiler.submit(pq, packet);
        }
    }
}

fn loadQueueReadIndex(queue: [*c]const c.hsa_queue_t) callconv(.C) u64 {
    if (profiler.getProfileQueue(queue)) |pq| {
        return @atomicLoad(u64, &pq.read_index, .Monotonic);
    } else {
        return profiler.hsa.queue_load_read_index_relaxed(queue);
    }
}

fn loadQueueWriteIndex(queue: [*c]const c.hsa_queue_t) callconv(.C) u64 {
    if (profiler.getProfileQueue(queue)) |pq| {
        return @atomicLoad(u64, &pq.write_index, .Monotonic);
    } else {
        return profiler.hsa.queue_load_write_index_relaxed(queue);
    }
}

fn storeQueueWriteIndex(queue: [*c]const c.hsa_queue_t, value: u64) callconv(.C) void {
    if (profiler.getProfileQueue(queue)) |pq| {
        @atomicStore(u64, &pq.write_index, value, .Monotonic);
    } else {
        profiler.hsa.queue_store_write_index_relaxed(queue, value);
    }
}

fn addQueueWriteIndex(queue: [*c]const c.hsa_queue_t, value: u64) callconv(.C) u64 {
    if (profiler.getProfileQueue(queue)) |pq| {
        return @atomicRmw(u64, &pq.write_index, .Add, value, .Monotonic);
    } else {
        return profiler.hsa.queue_add_write_index_relaxed(queue, value);
    }
}

export fn OnLoad(
    table: *c.ApiTable,
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

    table.core.queue_create = &queueCreate;
    table.core.queue_destroy = &queueDestroy;

    table.core.signal_store_relaxed = &signalStore;
    table.core.signal_store_screlease = &signalStore;

    // TODO: Override the remaining queue functions, for good measure.
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
