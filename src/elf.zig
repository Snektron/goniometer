//! This file defines some utilities for dealing with elf files.
const std = @import("std");
const pm4 = @import("pm4.zig");
const elf = std.elf;
const Allocator = std.mem.Allocator;

const Ehdr = elf.Elf64_Ehdr;
const Sym = elf.Elf64_Sym;
const Shdr = elf.Elf64_Shdr;

/// AMDGPU binaries are always elf64.
pub const alignment = @alignOf(elf.Ehdr);

pub const Binary = []align(alignment) const u8;

/// Get the (virtual) load address of a particular section.
pub fn getSectionVirtualAddr(bin: Binary, section: []const u8) !usize {
    if (bin.len < @sizeOf(elf.Ehdr))
        return error.InvalidElf;
    const header = elf.Header.parse(bin[0..@sizeOf(elf.Ehdr)]) catch return error.InvalidElf;

    if (!header.is_64 or header.endian != .little) {
        std.log.err("unexpected machine elf format for code object", .{});
        return error.InvalidElf;
    }

    const shdrs = std.mem.bytesAsSlice(Shdr, bin[header.shoff..])[0..header.shnum];
    const shstrtab_offset = shdrs[header.shstrndx].sh_offset;
    const shstrtab = bin[shstrtab_offset..];

    const shdr = for (shdrs) |shdr| {
        const sh_name = std.mem.sliceTo(shstrtab[shdr.sh_name..], 0);
        if (std.mem.eql(u8, sh_name, section))
            break shdr;
    } else return error.NoSuchSection;

    return shdr.sh_addr;
}

pub fn getGpuFunctions(a: Allocator, bin: Binary) !std.StringArrayHashMapUnmanaged([]const pm4.Word) {
    if (bin.len < @sizeOf(elf.Ehdr))
        return error.InvalidElf;
    const header = elf.Header.parse(bin[0..@sizeOf(elf.Ehdr)]) catch return error.InvalidElf;

    if (!header.is_64 or header.endian != .little) {
        std.log.err("unexpected machine elf format for code object", .{});
        return error.InvalidElf;
    }

    const shdrs = std.mem.bytesAsSlice(Shdr, bin[header.shoff..])[0..header.shnum];
    const shstrtab_offset = shdrs[header.shstrndx].sh_offset;
    const shstrtab = bin[shstrtab_offset..];

    const symtab_shdr = for (shdrs) |shdr| {
        const sh_name = std.mem.sliceTo(shstrtab[shdr.sh_name..], 0);
        if (std.mem.eql(u8, sh_name, ".symtab"))
            break shdr;
    } else return error.InvalidElf;

    const text_shdr = for (shdrs) |shdr| {
        const sh_name = std.mem.sliceTo(shstrtab[shdr.sh_name..], 0);
        if (std.mem.eql(u8, sh_name, ".text"))
            break shdr;
    } else return error.InvalidElf;

    const symtab = std.mem.bytesAsSlice(Sym, bin[symtab_shdr.sh_offset..][0..symtab_shdr.sh_size]);
    const text = bin[text_shdr.sh_offset..][0..text_shdr.sh_size];

    const strtab_offset = shdrs[symtab_shdr.sh_link].sh_offset;
    const strtab = bin[strtab_offset..];

    var functions = std.StringArrayHashMapUnmanaged([]const pm4.Word){};

    for (symtab) |sym| {
        const name = std.mem.sliceTo(strtab[sym.st_name..], 0);
        if (sym.st_info & 0xF != elf.STT_FUNC)
            continue; // We only care about functions.

        // st_value holds the _virtual_ address of the section. We know that it will point into the .text
        // section if everything is right, so we can subtract its virtual address to get the offset into the
        // text section
        const offset = sym.st_value - text_shdr.sh_addr;
        const code: []const pm4.Word = @alignCast(std.mem.bytesAsSlice(pm4.Word, text[offset..][0..sym.st_size]));
        try functions.put(a, try a.dupe(u8, name), try a.dupe(pm4.Word, code));

        // std.log.debug("found symbol: {s} {} {} {} {x}", .{name, sym.st_info & 0xF, offset, sym.st_size, code[code.len - 1]});
    }

    return functions;
}
