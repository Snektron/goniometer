//! This module implements a proxying HSA queue, that can be used to intercept
//! command packets from HSA.
const ProfileQueue = @This();

const std = @import("std");
const c = @import("c.zig");
const hsa_util = @import("hsa_util.zig");

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

pub fn create(
    hsa: *const c.CoreApiTable,
    a: std.mem.Allocator,
    agent: c.hsa_agent_t,
    size: u32,
    queue_type: c.hsa_queue_type32_t,
    callback: ?*const fn (c.hsa_status_t, [*c]c.hsa_queue_t, ?*anyopaque) callconv(.C) void,
    data: ?*anyopaque,
    private_segment_size: u32,
    group_segment_size: u32,
) !*ProfileQueue {
    _ = queue_type;
    _ = callback;
    _ = data;
    _ = private_segment_size;
    _ = group_segment_size;

    var backing_queue: [*c]c.hsa_queue_t = undefined;
    try hsa_util.check(hsa.queue_create(
        agent,
        size,
        c.HSA_QUEUE_TYPE_MULTI,
        null, // This is what rocprof does. Maybe this needs to be properly converted?
        null, // This is what rocprof does.
        std.math.maxInt(u32), // This is what rocprof does.
        std.math.maxInt(u32), // This is what rocprof does.
        &backing_queue,
    ));
    errdefer _ = hsa.queue_destroy(backing_queue);

    // Create our own packet buffer, doorbell, etc.
    var doorbell: c.hsa_signal_t = undefined;
    try hsa_util.check(hsa.signal_create(1, 0, null, &doorbell));
    errdefer _ = hsa.signal_destroy(doorbell);

    const packet_buf = try a.allocWithOptions(c.hsa_packet_t, size, c.hsa_packet_t.alignment, null);
    errdefer a.free(packet_buf);

    const self = try a.create(ProfileQueue); // Needs to be pinned in memory.
    self.* = ProfileQueue{
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
    return self;
}

pub fn destroy(self: *ProfileQueue, hsa: *const c.CoreApiTable, a: std.mem.Allocator) void {
    _ = hsa.queue_destroy(self.backing_queue);
    _ = hsa.signal_destroy(self.queue.doorbell_signal);
    a.free(self.packetBuffer());
    a.destroy(self);
}

pub fn packetBuffer(self: *ProfileQueue) []c.hsa_packet_t {
    return @ptrCast([*]c.hsa_packet_t, @alignCast(c.hsa_packet_t.alignment, self.queue.base_address.?))[0..self.queue.size];
}

pub fn backingPacketBuffer(self: *ProfileQueue) []c.hsa_packet_t {
    return @ptrCast([*]c.hsa_packet_t, @alignCast(c.hsa_packet_t.alignment, self.backing_queue.base_address.?))[0..self.backing_queue.size];
}

/// Submit a generic packet to an HSA queue. This function may block until there is enough
/// room for the packet.
pub fn submit(self: *ProfileQueue, hsa: *const c.CoreApiTable, packet: *const c.hsa_packet_t) void {
    const write_index = hsa.queue_add_write_index_scacq_screl(self.backing_queue, 1);

    // Busy loop until there is space.
    // TODO: Maybe this can be improved or something?
    while (write_index - hsa.queue_load_read_index_relaxed(self.backing_queue) >= self.backing_queue.size) {
        continue;
    }

    const slot_index = @intCast(u32, write_index % self.backing_queue.size);
    const slot = &self.backingPacketBuffer()[slot_index];

    // AQL packets have an 'invalid' header, which indicates that there is no packet at this
    // slot index yet - we want to overwrite that last, so that the packet is not read before
    // it is completely written.
    const packet_bytes = std.mem.asBytes(packet);
    const slot_bytes = std.mem.asBytes(slot);
    std.mem.copy(u8, slot_bytes[2..], packet_bytes[2..]);
    // Write the packet header atomically.
    @atomicStore(u16, &slot.header, packet.header, .Release);

    // Finally, ring the doorbell to notify the agent of the updated packet.
    hsa.signal_store_relaxed(self.backing_queue.doorbell_signal, @intCast(i64, write_index));
}
