//! Tool for dumping RGP structure to the command line

const std = @import("std");
const sqtt = @import("sqtt.zig");

pub const log_level = .info;

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var args = try std.process.argsAlloc(allocator);

    if (args.len != 2) {
        std.log.err("usage: {s} <file.rgp>", .{args[0]});
        std.os.exit(1);
    }

    const file = try std.fs.cwd().openFile(args[1], .{});
    defer file.close();

    var br = std.io.bufferedReader(file.reader());
    const in = br.reader();

    var bw = std.io.bufferedWriter(std.io.getStdOut().writer());
    const out = bw.writer();

    const header = try in.readStruct(sqtt.FileHeader);
    _ = header;

    var i: usize = 0;
    while (true) : (i += 1) {
        const chunk_header = in.readStruct(sqtt.ChunkHeader) catch |err| switch (err) {
            error.EndOfStream => break,
            else => |e| return e,
        };
        try out.print("{}: chunk {s} of {} bytes\n", .{ i, @tagName(chunk_header.chunk_id.chunk_type), chunk_header.size_bytes });
        try in.skipBytes(chunk_header.size_bytes - @sizeOf(sqtt.ChunkHeader), .{});
    }

    try bw.flush();
}
