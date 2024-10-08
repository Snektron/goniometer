//! Tool for dumping RGP structure to the command line

const std = @import("std");
const sqtt = @import("sqtt.zig");

pub const log_level = .info;

fn dump(name: []const u8, depth: usize, writer: anytype, val: anytype) !void {
    try writer.writeByteNTimes(' ', depth * 2);
    switch (@typeInfo(@TypeOf(val))) {
        .@"struct" => |info| {
            try writer.print("{s}:\n", .{name});
            inline for (info.fields) |field| {
                if (field.name[0] != '_') { // skip reserved and padding fields.
                    try dump(field.name, depth + 1, writer, @field(val, field.name));
                }
            }
        },
        .@"enum" => try writer.print("{s}: {s} ({}, 0x{x})\n", .{ name, @tagName(val), @intFromEnum(val), @intFromEnum(val) }),
        .array => |info| switch (info.child) {
            u8 => try writer.print("{s}: {s}\n", .{ name, val }),
            else => try writer.print("{s}: {any}\n", .{ name, val }),
        },
        .float => try writer.print("{s}: {d}\n", .{ name, val }),
        .int => try writer.print("{s}: {} (0x{x})\n", .{ name, val, val }),
        else => try writer.print("{s}: {}\n", .{ name, val }),
    }
}

fn dumpCodeObjectDb(out: anytype, name: []const u8, data: []align(0x1000) const u8) !void {
    const db = @as(*const sqtt.CodeObjectDatabase, @ptrCast(data.ptr)).*;
    try dump(name, 0, out, db);

    // Note: actually this is db.offset + @sizeOf(sqtt.CodeObjectDatabase),
    // but it seems that PAL puts it right after too.
    var offset: usize = @sizeOf(sqtt.CodeObjectDatabase);
    var i: usize = 0;
    while (i < db.record_count) : (i += 1) {
        const record: *const sqtt.CodeObjectDatabase.Record = @ptrCast(@alignCast(&data[offset]));
        offset += @sizeOf(sqtt.CodeObjectDatabase.Record);
        // const binary = data[offset..][0..record.record_size];
        offset += record.record_size;
        try out.print(
            \\  record {}:
            \\    record_size: {}
            \\
        ,
            .{ i, record.record_size },
        );
    }
    try out.print("  size adds up: {}\n", .{offset == db.header.size_bytes});
}

fn dumpPsoCorrelation(out: anytype, name: []const u8, data: []align(0x1000) const u8) !void {
    const pso = @as(*const sqtt.PsoCorrelation, @ptrCast(data.ptr)).*;
    try dump(name, 0, out, pso);

    // In practise the offset is always behind the struct.
    var offset: usize = @sizeOf(sqtt.PsoCorrelation);
    var i: usize = 0;
    while (i < pso.record_count) : (i += 1) {
        const record: *const sqtt.PsoCorrelation.Record = @ptrCast(@alignCast(&data[offset]));
        offset += pso.record_size;
        try out.print("  record {}:\n", .{i});
        try dump("record", 2, out, record.*);
    }
}

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const args = try std.process.argsAlloc(allocator);

    if (args.len != 2) {
        std.log.err("usage: {s} <file.rgp>", .{args[0]});
        std.posix.exit(1);
    }

    const file = try std.fs.cwd().openFile(args[1], .{});
    defer file.close();

    var br = std.io.bufferedReader(file.reader());
    const in = br.reader();

    var bw = std.io.bufferedWriter(std.io.getStdOut().writer());
    const out = bw.writer();

    const header = try in.readStruct(sqtt.FileHeader);
    try dump("file header", 0, out, header);

    var buf = std.ArrayListAligned(u8, 0x1000).init(allocator);

    var i: usize = 0;
    var offset: usize = @intCast(header.chunk_offset);
    while (true) : (i += 1) {
        const chunk_header = in.readStruct(sqtt.ChunkHeader) catch |err| switch (err) {
            error.EndOfStream => break,
            else => |e| return e,
        };
        try buf.resize(chunk_header.size_bytes);
        @memcpy(buf.items[0..@sizeOf(sqtt.ChunkHeader)], std.mem.asBytes(&chunk_header));
        try in.readNoEof(buf.items[@sizeOf(sqtt.ChunkHeader)..]);

        const name = try std.fmt.allocPrint(allocator, "chunk {} at 0x{x}", .{ i, offset });
        offset += chunk_header.size_bytes;
        switch (chunk_header.chunk_id.chunk_type) {
            .cpu_info => try dump(name, 0, out, @as(*const sqtt.CpuInfo, @ptrCast(buf.items.ptr)).*),
            .asic_info => try dump(name, 0, out, @as(*const sqtt.AsicInfo, @ptrCast(buf.items.ptr)).*),
            .api_info => try dump(name, 0, out, @as(*const sqtt.ApiInfo, @ptrCast(buf.items.ptr)).*),
            .sqtt_desc => try dump(name, 0, out, @as(*const sqtt.SqttDesc, @ptrCast(buf.items.ptr)).*),
            .sqtt_data => try dump(name, 0, out, @as(*const sqtt.SqttData, @ptrCast(buf.items.ptr)).*),
            .code_object_database => try dumpCodeObjectDb(out, name, buf.items),
            .pso_correlation => try dumpPsoCorrelation(out, name, buf.items),
            else => {
                try dump(name, 0, out, .{ .header = chunk_header });
            },
        }
    }

    try bw.flush();
}
