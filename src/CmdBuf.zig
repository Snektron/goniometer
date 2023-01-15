//! A PM4 command buffer, managed by HSA memory.
const Self = @This();

const std = @import("std");
const pm4 = @import("pm4.zig");
const hsa = @import("hsa.zig");

pub const Pkt3Options = struct {
    predicate: bool = false,
    shader_type: pm4.ShaderType = .graphics,
};

/// The current size of this command buffer in words.
size: u32 = 0,
/// The command buffer's capacity, in words.
cap: u32,
/// Pointer the to command buffer's data.
buf: [*]pm4.Word,

pub fn alloc(instance: *const hsa.Instance, pool: hsa.MemoryPool, cap: u32) !Self {
    const buf = try instance.memoryPoolAllocate(pm4.Word, pool, cap);
    return Self{
        .cap = cap,
        .buf = buf.ptr,
    };
}

pub fn free(self: *Self, instance: *const hsa.Instance) void {
    instance.memoryPoolFree(self.buf);
    self.* = undefined;
}

pub fn words(self: *const Self) []pm4.Word {
    return self.buf[0..self.size];
}

fn emit(self: *Self, packet: []const pm4.Word) void {
    std.debug.assert(self.size + packet.len <= self.cap);
    const buf = self.buf + self.size;
    for (packet) |word, i| {
        buf[i] = word;
    }
    self.size += @intCast(u32, packet.len);
}

/// Converts a pointer-to-struct to a packet slice.
fn asWords(ptr: anytype) []const pm4.Word {
    const Child = std.meta.Child(@TypeOf(ptr));
    std.debug.assert(@bitSizeOf(Child) % @bitSizeOf(pm4.Word) == 0);
    return @ptrCast([*]const u32, ptr)[0 .. @bitSizeOf(Child) / @bitSizeOf(pm4.Word)];
}

fn pkt2(self: *Self) void {
    const header = pm4.Pkt2Header{};
    self.emit(asWords(&header));
}

pub fn nop(self: *Self) void {
    self.pkt2();
}

fn pkt3Header(self: *Self, opcode: pm4.Opcode, opts: Pkt3Options, data_words: usize) void {
    std.debug.assert(self.size + 1 + data_words <= self.cap);
    const header = pm4.Pkt3Header{
        .predicate = opts.predicate,
        .shader_type = opts.shader_type,
        .opcode = opcode,
        .count_minus_one = @intCast(u14, data_words - 1),
    };
    self.emit(asWords(&header));
}

fn pkt3(self: *Self, opcode: pm4.Opcode, opts: Pkt3Options, data: []const u32) void {
    self.pkt3Header(opcode, opts, data.len);
    self.emit(data);
}

pub fn setShReg(self: *Self, comptime reg: pm4.ShRegister, value: reg.Type()) void {
    self.setShRegs(reg, &.{@bitCast(u32, value)});
}

pub fn setShRegs(self: *Self, start_reg: pm4.ShRegister, values: []const u32) void {
    self.pkt3Header(.set_sh_reg, .{}, values.len + 1);
    self.emit(&.{start_reg.address()});
    self.emit(values);
}

pub fn setUConfigReg(self: *Self, comptime reg: pm4.UConfigRegister, value: reg.Type()) void {
    self.setUConfigRegs(reg, &.{@bitCast(u32, value)});
}

pub fn setUConfigRegs(self: *Self, start_reg: pm4.UConfigRegister, values: []const u32) void {
    self.pkt3Header(.set_uconfig_reg, .{}, values.len + 1);
    self.emit(&.{start_reg.address()});
    self.emit(values);
}

pub fn setPrivilegedConfigReg(self: *Self, comptime reg: pm4.PrivilegedRegister, value: reg.Type()) void {
    self.copyData(.{
        .control = .{
            .src_sel = .imm,
            .dst_sel = .perf,
            .count_sel = 0,
            .wr_confirm = false,
            .engine_sel = 0,
        },
        .src_addr = @bitCast(u32, value),
        .dst_addr = reg.address(),
    });
}

pub fn writeEventNonSample(self: *Self, event_type: pm4.EventWrite.EventType, index: u4) void {
    const event_write = pm4.EventWrite{
        .event_type = event_type,
        .event_index = index,
        .addr = 0,
    };
    // Non-sample events dont need the extra address, apparently.
    // This makes the difference between a hang or not.
    self.pkt3(.event_write, .{}, asWords(&event_write)[0..1]);
}

pub fn copyData(self: *Self, copy_data: pm4.CopyData) void {
    self.pkt3(.copy_data, .{}, asWords(&copy_data));
}

pub fn waitRegMem(
    self: *Self,
    wait_reg_mem: pm4.WaitRegMem,
) void {
    self.pkt3(.wait_reg_mem, .{}, asWords(&wait_reg_mem));
}

pub fn indirectBuffer(self: *Self, buf: []const pm4.Word) void {
    const ib = pm4.IndirectBuffer{
        .swap = 0,
        .ib_base = @truncate(u62, @ptrToInt(buf.ptr) >> 2),
        .size = @intCast(u20, buf.len),
        .chain = 0,
        .offload_polling = 0,
        .valid = 1, // this is what aqlprofile does
        .vmid = 0,
        .cache_policy = 1, // this is what aqlprofile does
    };
    self.pkt3(.indirect_buffer, .{}, asWords(&ib));
}

pub const FlushFlags = packed struct {
    icache: bool = false,
    scache: bool = false,
    vcache: bool = false,
    l2: bool = false,
    cs_partial_flush: bool = false,
};

pub fn cacheFlush(self: *Self, flags: FlushFlags) void {
    var grc = @bitCast(pm4.AcquireMem.GcrCntl, @as(u32, 0));

    if (flags.icache) {
        grc.gli_inv = .all;
    }
    if (flags.scache) {
        grc.gl1_inv = true;
        grc.glk_inv = true;
    }
    if (flags.vcache) {
        grc.gl1_inv = true;
        grc.glv_inv = true;
    }
    if (flags.l2) {
        grc.gl2_inv = true;
        grc.gl2_wb = true;
        grc.glm_inv = true;
        grc.glm_wb = true;
    }

    if (flags.cs_partial_flush) {
        self.writeEventNonSample(.cs_partial_flush, 4);
    }

    const acquire = pm4.AcquireMem{
        .coher_cntl = 0,
        .coher_size = 0xffff_ffff,
        .coher_base = 0xff_ffff,
        .poll_interval = 0xa,
        .gcr_cntl = grc,
    };
    self.pkt3(.acquire_mem, .{}, asWords(&acquire));
}

pub fn sqttMarker(self: *Self, comptime Marker: type, marker: *const Marker) void {
    self.sqttDataMarker(asWords(marker));
}

pub fn sqttDataMarker(self: *Self, data: []const pm4.Word) void {
    // Writing the SQTT user data is used by alternating between sqtt_userdata_2 and sqtt_userdata_3,
    // which are sequentially in the uconfig register address space.
    const words_per_batch = 2;
    var i: usize = 0;
    while (i < data.len) : (i += words_per_batch) {
        const words_to_write = @min(data.len - i, words_per_batch);
        self.setUConfigRegs(.sqtt_userdata_2, data[i..][0..words_to_write]);
    }
}
