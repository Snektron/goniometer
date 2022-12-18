const std = @import("std");
const c = @import("c.zig");
const Profiler = @import("Profiler.zig");
const ProfileQueue = @import("ProfileQueue.zig");

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
    // TODO: Thread safety.
    // std.log.debug("testing aqlprofile", .{});
    // const event = c.hsa_ven_amd_aqlprofile_event_t{
    //     .block_name = c.HSA_VEN_AMD_AQLPROFILE_BLOCK_NAME_SQ,
    //     .block_index = 0,
    //     .counter_id = 0,
    // };

    // const params = [_]c.hsa_ven_amd_aqlprofile_parameter_t{
    //     .{
    //         .parameter_name = c.HSA_VEN_AMD_AQLPROFILE_PARAMETER_NAME_MASK,
    //         .value = 0,
    //     },
    //     .{
    //         .parameter_name = c.HSA_VEN_AMD_AQLPROFILE_PARAMETER_NAME_TOKEN_MASK,
    //         .value = 0,
    //     },
    // };

    // var profile = c.hsa_ven_amd_aqlprofile_profile_t{
    //     .agent = agent,
    //     .type = c.HSA_VEN_AMD_AQLPROFILE_EVENT_TYPE_PMC,
    //     .events = &event,
    //     .event_count = 1,
    //     .parameters = &params,
    //     .parameter_count = params.len,
    //     .output_buffer = .{
    //         .ptr = null,
    //         .size = 0,
    //     },
    //     .command_buffer = .{
    //         .ptr = null,
    //         .size = 0,
    //     },
    // };

    // var start_packet: c.hsa_ext_amd_aql_pm4_packet_t = undefined;
    // const status = profiler.aqlprofile.start(&profile, &start_packet);
    // std.log.debug("status: {}", .{status});
    // std.debug.assert(status == c.HSA_STATUS_SUCCESS);

    // std.log.debug("output buffer: {}", .{ profile.output_buffer });
    // std.log.debug("command buffer: {}", .{ profile.command_buffer });

    // std.log.debug("seems to be OK", .{});
    // std.log.debug("packet dump:", .{});
    // std.log.debug("  header: 0x{X}", .{start_packet.header});
    // for (start_packet.pm4_command) |cmd| {
    //     std.log.debug("0x{X}", .{cmd});
    // }

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
        return switch (err) {
            error.OutOfMemory => c.HSA_STATUS_ERROR_OUT_OF_RESOURCES,
            else => c.HSA_STATUS_ERROR,
        };
    };

    return c.HSA_STATUS_SUCCESS;
}

fn queueDestroy(queue: [*c]c.hsa_queue_t) callconv(.C) c.hsa_status_t {
    // TODO: Thread safety
    std.log.debug("queueDestroy", .{});
    profiler.destroyQueue(queue) catch |err| switch (err) {
        error.InvalidQueue => std.log.err("application tried to destroy an invalid queue", .{}),
    };
    return c.HSA_STATUS_SUCCESS;
}

fn signalStore(signal: c.hsa_signal_t, queue_index: c.hsa_signal_value_t) callconv(.C) void {
    std.log.debug("signalStore: 0x{x} {}", .{ signal.handle, queue_index });

    const pq = profiler.queues.get(signal) orelse {
        // No such queue, so this is probably a signal for something else.
        profiler.hsa.hsa_signal_store_relaxed_fn(signal, queue_index);
        return;
    };

    const begin = @atomicRmw(u64, &pq.read_index, .Xchg, @intCast(u64, queue_index + 1), .Monotonic);
    const end = @atomicLoad(u64, &pq.write_index, .Monotonic);

    const packet_buf = pq.packetBuffer();
    var i = begin;
    while (i < end) : (i += 1) {
        const index = i % pq.queue.size;
        pq.submit(&profiler.hsa, &packet_buf[index]);
    }
}

fn loadQueueReadIndex(queue: [*c]const c.hsa_queue_t) callconv(.C) u64 {
    if (profiler.getProfileQueue(queue)) |pq| {
        return @atomicLoad(u64, &pq.read_index, .Monotonic);
    } else {
        return profiler.hsa.hsa_queue_load_read_index_relaxed_fn(queue);
    }
}

fn loadQueueWriteIndex(queue: [*c]const c.hsa_queue_t) callconv(.C) u64 {
    if (profiler.getProfileQueue(queue)) |pq| {
        return @atomicLoad(u64, &pq.write_index, .Monotonic);
    } else {
        return profiler.hsa.hsa_queue_load_write_index_relaxed_fn(queue);
    }
}

fn storeQueueWriteIndex(queue: [*c]const c.hsa_queue_t, value: u64) callconv(.C) void {
    if (profiler.getProfileQueue(queue)) |pq| {
        @atomicStore(u64, &pq.write_index, value, .Monotonic);
    } else {
        profiler.hsa.hsa_queue_store_write_index_relaxed_fn(queue, value);
    }
}

fn addQueueWriteIndex(queue: [*c]const c.hsa_queue_t, value: u64) callconv(.C) u64 {
    if (profiler.getProfileQueue(queue)) |pq| {
        return @atomicRmw(u64, &pq.write_index, .Add, value, .Monotonic);
    } else {
        return profiler.hsa.hsa_queue_add_write_index_relaxed_fn(queue, value);
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

    std.log.debug("overriding hsa functions", .{});
    table.core.hsa_queue_create_fn = &queueCreate;
    table.core.hsa_queue_destroy_fn = &queueDestroy;

    table.core.hsa_signal_store_relaxed_fn = &signalStore;
    table.core.hsa_signal_store_screlease_fn = &signalStore;

    // TODO: Override the remaining queue functions, for good measure.
    // TODO: Use the proper atomic ordering.
    table.core.hsa_queue_load_read_index_relaxed_fn = &loadQueueReadIndex;
    table.core.hsa_queue_load_read_index_scacquire_fn = &loadQueueReadIndex;

    table.core.hsa_queue_load_write_index_relaxed_fn = &loadQueueWriteIndex;
    table.core.hsa_queue_load_write_index_scacquire_fn = &loadQueueWriteIndex;

    table.core.hsa_queue_store_write_index_relaxed_fn = &storeQueueWriteIndex;
    table.core.hsa_queue_store_write_index_screlease_fn = &storeQueueWriteIndex;

    table.core.hsa_queue_add_write_index_scacq_screl_fn = &addQueueWriteIndex;
    table.core.hsa_queue_add_write_index_scacquire_fn = &addQueueWriteIndex;
    table.core.hsa_queue_add_write_index_relaxed_fn = &addQueueWriteIndex;
    table.core.hsa_queue_add_write_index_screlease_fn = &addQueueWriteIndex;

    return true;
}
