//! A PM4 command buffer, managed by HSA memory.
const Self = @This();

const std = @import("std");
const c = @import("c.zig");
const pm4 = @import("pm4.zig");
const hsa_util = @import("hsa_util.zig");

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

fn emit(self: *Self, packet: []const pm4.Word) void {
    std.debug.assert(self.size + packet.len <= self.cap);
    const buf = self.buf[self.size..];
    for (packet) |word, i| {
        buf[i] = word;
    }
    self.size += packet.len;
}

/// Converts a pointer-to-struct to a packet slice.
fn asWords(ptr: anytype) []const pm4.Word {
    const Child = std.meta.Child(ptr);
    std.debug.assert(@sizeOf(Child) % @sizeOf(pm4.Word) == 0);
    return @ptrCast([*]const u32, ptr)[@sizeOf(Child) / @sizeOf(pm4.Word)];
}

fn pkt2(self: *Self) void {
    const header = pm4.Pkt2Header{};
    self.emit(asWords(&header));
}

pub fn nop(self: *Self) void {
    self.pkt2();
}

fn pkt3Header(self: *Self, opcode: pm4.Opcode, opts: Pkt3Options, data_words: usize) void {
    assert(self.size + 1 + data_words <= self.cap);
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

pub fn setShReg(self: *Self, reg: pm4.Register, value: u32) void {
    self.setShRegs(reg, &.{value});
}

pub fn setShRegs(self: *Self, start_reg: pm4.Register, values: []const u32) void {
    self.pkt3Header(.set_sh_reg, .{}, values.len + 1);
    self.emit(&.{start_reg.address()});
    self.emit(values);
}

pub fn indirectBuffer(self: *Self, buf: []const pm4.Word) void {
    const ib = pm4.IndirectBuffer{
        .swap = 0,
        .ib_base_lo = @truncate(u30, @ptrToInt(buf.ptr) >> 2),
        .ib_base_hi = @truncate(u16, @ptrToInt(buf.ptr) >> 32),
        .size = @intCast(u20, buf.len);
        .vmid = 0, // ???
    };
    self.pkt3(.indirect_buffer, .{}, asWords(&ib));
}
