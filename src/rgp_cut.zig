//! Quick tool to remove some chunks from an RGP file, for testing.

const std = @import("std");
const sqtt = @import("sqtt.zig");

pub const log_level = .info;

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var args = try std.process.argsAlloc(allocator);

    if (args.len < 4) {
        std.log.err("usage: {s} <in.rgp> <out.rgp> <chunk selectors...>", .{args[0]});
        std.os.exit(1);
    }

    var chunks_to_keep = std.ArrayList(bool).init(allocator);
    for (args[3..]) |sel| {
        const nr = try std.fmt.parseInt(u32, sel, 10);
        if (chunks_to_keep.items.len <= nr)
            try chunks_to_keep.resize(nr + 1);
        chunks_to_keep.items[nr] = true;
    }

    const in_file = try std.fs.cwd().openFile(args[1], .{});
    defer in_file.close();

    const out_file = try std.fs.cwd().createFile(args[2], .{});
    defer out_file.close();

    var br = std.io.bufferedReader(in_file.reader());
    const in = br.reader();

    var bw = std.io.bufferedWriter(out_file.writer());
    const out = bw.writer();

    const header = try in.readStruct(sqtt.FileHeader);
    // Always keep the header.
    try out.writeStruct(header);

    var buf = std.ArrayList(u8).init(allocator);

    var i: usize = 0;
    while (true) : (i += 1) {
        if (i >= chunks_to_keep.items.len)
            break;

        const chunk_header = in.readStruct(sqtt.ChunkHeader) catch |err| switch (err) {
            error.EndOfStream => break,
            else => |e| return e,
        };
        const body_size = chunk_header.size_bytes - @sizeOf(sqtt.ChunkHeader);
        try buf.resize(body_size);
        try in.readNoEof(buf.items);

        if (chunks_to_keep.items[i]) {
            try out.writeStruct(chunk_header);
            try out.writeAll(buf.items);
        }
    }

    try bw.flush();
}
