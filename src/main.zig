const std = @import("std");
const c = @import("c.zig");
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
    callback: ?*const fn(c.hsa_status_t, [*c]c.hsa_queue_t, ?*anyopaque) callconv(.C) void,
    data: ?*anyopaque,
    private_segment_size: u32,
    group_segment_size: u32,
    queue: [*c][*c]c.hsa_queue_t,
) callconv(.C) c.hsa_status_t {
    std.log.debug("testing aqlprofile", .{});
    // const event = c.hsa_ven_amd_aqlprofile_event_t{
    //     .block_name = c.HSA_VEN_AMD_AQLPROFILE_BLOCK_NAME_SQ,
    //     .block_index = 0,
    //     .counter_id = 4,
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
    //     .type = c.HSA_VEN_AMD_AQLPROFILE_EVENT_TYPE_TRACE,
    //     .events = null,
    //     .event_count = 0,
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

    const result = profiler.hsa_core.hsa_queue_create_fn(
        agent,
        size,
        queue_type,
        callback,
        data,
        private_segment_size,
        group_segment_size,
        queue,
    );

    profiler.createQueue(queue.*) catch |err| {
        std.log.err("failed to track new HSA queue: {s}", .{@errorName(err)});
    };

    return result;
}

fn queueDestroy(queue: [*c]c.hsa_queue_t) callconv(.C) c.hsa_status_t {
    std.log.debug("queueDestroy", .{});
    profiler.destroyQueue(queue) catch |err| switch (err) {
        error.InvalidQueue => std.log.err("application tried to destroy an invalid queue", .{}),
    };
    return profiler.hsa_core.hsa_queue_destroy_fn(queue);
}

fn signalStore(signal: c.hsa_signal_t, queue_index: c.hsa_signal_value_t) callconv(.C) void {
    std.log.debug("signalStore: {X} {}", .{ signal.handle, queue_index});

    // Get the tracked queue information that fits with this queue
    const queue_info = profiler.queues.getPtr(signal) orelse {
        // No such queue, so this is probably a signal for something else.
        profiler.hsa_core.hsa_signal_store_relaxed_fn(signal, queue_index);
        return;
    };

    const begin = queue_info.last_index;
    const end = @intCast(usize, queue_index + 1);
    queue_info.last_index = end;

    std.log.debug("application submitted {} packet(s)", .{end - begin});

    const queue_base = @ptrCast([*]c.hsa_packet_t, @alignCast(c.hsa_packet_t.alignment, queue_info.queue.base_address.?));

    var i = begin;
    while (i < end) : (i += 1) {
        const index = i % queue_info.queue.size;
        const packet = &queue_base[index];
        if (packet.packetType() != c.HSA_PACKET_TYPE_KERNEL_DISPATCH)
            continue;

        // const dispatch_packet = @ptrCast(*c.hsa_kernel_dispatch_packet_t, packet);
        // TODO: Get kernel name? This is kind of annoying and requires another bunch of extensions,
        // so maybe do it later.
    }

    profiler.hsa_core.hsa_signal_store_relaxed_fn(signal, queue_index);
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
    table.core.hsa_signal_store_relaxed_fn = &signalStore;
    table.core.hsa_signal_store_screlease_fn = &signalStore;
    table.core.hsa_queue_create_fn = &queueCreate;
    table.core.hsa_queue_destroy_fn = &queueDestroy;

    return true;
}
