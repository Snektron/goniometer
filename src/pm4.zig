//! This file defines PM4 constants and types.

pub const Word = u32;

pub const ShaderType = enum(u1) {
    graphics = 0,
    compuate = 1,
};

pub const Pkt2Header = packed struct(Word) {
    _reserved: u30 = 0,
    packet_type: u2 = 0x2,
};

pub const Pkt3Header = packed struct(Word) {
    predicate: bool,
    shader_type: ShaderType,
    _reserved: u6 = 0,
    opcode: Opcode,
    count_minus_one: u14,
    packet_type: u2 = 0x3,
};

/// SH Registers. Note: value is byte offset, not word offset.
pub const ShRegister = enum(u16) {
    pub const base = 0xB000;

    compute_thread_trace_enable = 0xB878,

    pub fn address(self: ShRegister) u16 {
        return (@enumToInt(self) - base) / @sizeOf(u32);
    }

    pub fn Type(comptime self: ShRegister) type {
        return switch (self) {
            .compute_thread_trace_enable => packed struct(u32) {
                enable: bool,
                _reserved: u31 = 0,
            },
        };
    }
};

/// UCONFIG registers. TODO: find out if they need to be merged with the above.
pub const UConfigRegister = enum(u32) {
    pub const base = 0x30000;

    grbm_gfx_index = 0x30800,
    sqtt_userdata_2 = 0x30D08,
    spi_config_cntl = 0x31100,
    cp_perfmon_cntl = 0x36020,
    rlc_perfmon_clock_cntl = 0x37390,

    pub fn address(self: UConfigRegister) u32 {
        return (@enumToInt(self) - base) / @sizeOf(u32);
    }

    pub fn Type(comptime self: UConfigRegister) type {
        return switch (self) {
            .spi_config_cntl => packed struct(u32) {
                gpr_write_priority: u21,
                exp_priority_order: u3,
                enable_sqg_top_events: bool,
                enable_sqg_bop_events: bool,
                rsrc_mgmt_reset: bool,
                ttrace_stall_all: bool,
                alloc_arb_lru_ena: bool,
                exp_arb_lru_ena: bool,
                ps_pkr_priority_cntl: u2,
            },
            .grbm_gfx_index => packed struct(u32) {
                instance_index: u8,
                sa_index: u8,
                se_index: u8,
                _reserved: u5 = 0,
                sa_broadcast_writes: bool,
                instance_broadcast_writes: bool,
                se_broadcast_writes: bool,
            },
            .cp_perfmon_cntl => packed struct(u32) {
                pub const State = enum(u4) {
                    disable_and_reset = 0,
                    start_counting = 1,
                    stop_count = 2,
                    disable_and_reset_phantom = 4,
                    count_and_dump_pantom = 5,
                };

                pub const Mode = enum(u2) {
                    always_count = 0,
                    count_context_true = 2,
                    count_context_false = 3,
                };

                perfmon_state: State,
                spm_perfmon_state: State,
                enable_mode: Mode,
                sample_enable: bool,
                _reserved: u21 = 0,
            },
            .rlc_perfmon_clock_cntl => packed struct(u32) {
                inhibit_clock: bool,
                _reserved: u31 = 0,
            },
            .sqtt_userdata_2 => u32,
        };
    }
};

pub const PrivilegedRegister = enum(u16) {
    sqtt_buf0_base = 0x8D00,
    sqtt_buf0_size = 0x8D04,
    sqtt_mask = 0x8D14,
    sqtt_token_mask = 0x8D18,
    sqtt_ctrl = 0x8D1C,
    sqtt_wptr = 0x8D10,
    sqtt_status = 0x8D20,
    sqtt_dropped_cntr = 0x8D24,

    pub fn address(self: PrivilegedRegister) u32 {
        return @enumToInt(self) / @sizeOf(u32);
    }

    pub fn Type(comptime self: PrivilegedRegister) type {
        return switch (self) {
            .sqtt_buf0_base => u32,
            .sqtt_buf0_size => packed struct(u32) {
                base_hi: u8,
                size: u24,
            },
            .sqtt_mask => packed struct(u32) {
                simd_sel: u2,
                _reserved1: u2 = 0,
                wgp_sel: u4,
                _reserved2: u1 = 0,
                sa_sel: u1,
                wtype_include: u7,
                _reserved3: u15 = 0,
            },
            .sqtt_token_mask => packed struct(u32) {
                pub const TokenExclude = packed struct(u12) {
                    vmemexec: bool = false,
                    aluexec: bool = false,
                    valuinst: bool = false,
                    waverdy: bool = false,
                    wavestartend: bool = false,
                    immediate: bool = false,
                    reg: bool = false,
                    event: bool = false,
                    inst: bool = false,
                    utilctr: bool = false,
                    wavealloc: bool = false,
                    perf: bool = false,
                };

                pub const RegInclude = packed struct(u8) {
                    sqdec: bool = false,
                    shdec: bool = false,
                    gfxudec: bool = false,
                    comp: bool = false,
                    context: bool = false,
                    config: bool = false,
                    other: bool = false,
                    reads: bool = false,
                };

                token_exclude: TokenExclude,
                bop_events_token_include: bool,
                _reserved1: u3 = 0,
                reg_include: RegInclude,
                inst_exclude: u3,
                _reserved2: u1 = 0,
                reg_exclude: u3,
                reg_detail_all: bool,
            },
            .sqtt_ctrl => packed struct(u32) {
                mode: u2 = 0,
                all_vmid: bool = false,
                ch_perf_en: bool = false,
                interrupt_en: bool = false,
                double_buffer: bool = false,
                hiwater: u3 = 0,
                reg_stall_en: bool = false,
                spi_stall_en: bool = false,
                sq_stall_en: bool = false,
                reg_drop_on_stall: bool = false,
                util_timer: bool = false,
                wavestart_mode: u2 = 0,
                rt_freq: u2 = 0,
                sync_count_markers: bool = false,
                sync_count_draws: bool = false,
                lowater_offset: u3 = 0,
                _reserved1: u5 = 0,
                auto_flush_padding_dis: bool = false,
                auto_flush_mode: bool = false,
                capture_all: bool = false,
                draw_event_en: bool = false,
            },
            .sqtt_status => packed struct(u32) {
                finish_pending: u12 = 0,
                finish_done: u12 = 0,
                utc_err: bool = false,
                busy: bool = false,
                event_cntr_overflow: bool = false,
                event_cntr_stall: bool = false,
                owner_vmid: u4 = 0,
            },
            else => unreachable, // TODO: translate these structure types.
        };
    }
};

// Apparently there are multiple types of this packet, depending on
// engine type. This is the "compute" version.
pub const IndirectBuffer = packed struct(u96) {
    swap: u2,
    ib_base: u62,
    size: u20,
    chain: u1,
    offload_polling: u1,
    _reserved1: u1 = 0,
    valid: u1,
    vmid: u4,
    cache_policy: u2,
    _reserved2: u2 = 0,
};

pub const CopyData = packed struct(u160) {
    pub const SrcSel = enum(u4) {
        mem_mapped_reg = 0,
        memory = 1,
        tc_l2 = 2,
        gds = 3,
        perf = 4,
        imm = 5,
        atomic_rtn = 6,
        gds_atomic_rtn_0 = 7,
        gds_atomic_rtn_1 = 8,
    };

    pub const DstSel = enum(u3) {
        mem_mapped_reg = 0,
        memory_sync = 1,
        tc_l2 = 2,
        gds = 3,
        perf = 4,
        memory_async = 5,
    };

    const Control = packed struct(u32) {
        src_sel: SrcSel, // bits 0-3
        _reserved1: u4 = 0,
        dst_sel: DstSel, // bits 8-11
        _reserved2: u5 = 0,
        count_sel: u1, // bit 16
        _reserved3: u3 = 0,
        wr_confirm: bool, // bit 20
        _reserved4: u9 = 0,
        engine_sel: u2, // bits 30-31
    };

    control: Control,
    src_addr: u64,
    dst_addr: u64,
};

pub const EventWrite = packed struct(u96) {
    pub const EventType = enum(u8) {
        cs_partial_flush = 7,
        thread_trace_start = 51,
        thread_trace_stop = 52,
        thread_trace_finish = 55,
        _,
    };

    event_type: EventType,
    event_index: u4,
    _reserved1: u20 = 0,
    addr: u64,
};

pub const WaitRegMem = packed struct(u192) {
    pub const Function = enum(u3) {
        always = 0b000,
        lt = 0b001,
        lte = 0b010,
        eq = 0b011,
        ne = 0b100,
        gte = 0b101,
        gt = 0b110,
    };

    pub const MemSpace = enum(u1) {
        register = 0,
        memory = 1,
    };

    pub const Engine = enum(u1) {
        me = 0,
        pfp = 1,
    };

    function: Function,
    _reserved1: u1 = 0,
    mem_space: MemSpace,
    _reserved2: u3 = 0,
    engine: Engine,
    _reserved3: u23 = 0,
    poll_addr: u64,
    reference: u32,
    mask: u32,
    poll_interval: u16,
    _reserved4: u16 = 0,
};

pub const AcquireMem = packed struct(u224) {
    pub const GcrCntl = packed struct(u32) {
        pub const GliInv = enum(u2) {
            nop = 0,
            all = 1,
            range = 2,
            first_last = 3,
        };

        pub const Gl1Range = enum(u2) {
            all = 0,
            range = 2,
            first_last = 3,
        };

        pub const Gl2Range = enum(u2) {
            all = 0,
            vol = 1,
            range = 2,
            first_last = 3,
        };

        pub const Seq = enum(u2) {
            parallel = 0,
            forward = 1,
            reverse = 2,
        };

        gli_inv: GliInv,
        gl1_range: Gl1Range,
        glm_wb: bool,
        glm_inv: bool,
        glk_wb: bool,
        glk_inv: bool,
        glv_inv: bool,
        gl1_inv: bool,
        gl2_us: bool,
        gl2_range: Gl2Range,
        gl2_discard: bool,
        gl2_inv: bool,
        gl2_wb: bool,
        seq: Seq,
        range_is_pa: bool,
        _reserved: u13 = 0,
    };

    coher_cntl: u32,
    coher_size: u64,
    coher_base: u64,
    poll_interval: u32,
    gcr_cntl: GcrCntl,
};

// Taken from https://github.com/GPUOpen-Drivers/pal/blob/dev/src/core/hw/gfxip/gfx9/chip/gfx9_plus_merged_pm4_it_opcodes.h
// zig fmt: off
pub const Opcode = enum(u8) {
    nop                                          = 0x10,
    set_base                                     = 0x11,
    index_buffer_size                            = 0x13,
    dispatch_direct                              = 0x15,
    dispatch_indirect                            = 0x16,
    indirect_buffer_end                          = 0x17,
    indirect_buffer_cnst_end                     = 0x19,
    atomic_gds                                   = 0x1d,
    atomic_mem                                   = 0x1e,
    occlusion_query                              = 0x1f,
    set_predication                              = 0x20,
    reg_rmw                                      = 0x21,
    cond_exec                                    = 0x22,
    pred_exec                                    = 0x23,
    draw_indirect                                = 0x24,
    draw_index_indirect                          = 0x25,
    index_base                                   = 0x26,
    draw_index_2                                 = 0x27,
    context_control                              = 0x28,
    index_type                                   = 0x2a,
    draw_indirect_multi                          = 0x2c,
    draw_index_auto                              = 0x2d,
    num_instances                                = 0x2f,
    draw_index_multi_auto                        = 0x30,
    indirect_buffer_priv                         = 0x32,
    indirect_buffer_cnst                         = 0x33,
    strmout_buffer_update                        = 0x34,
    draw_index_offset_2                          = 0x35,
    draw_preamble                                = 0x36,
    write_data                                   = 0x37,
    draw_index_indirect_multi                    = 0x38,
    mem_semaphore                                = 0x39,
    draw_index_multi_inst                        = 0x3a,
    copy_dw                                      = 0x3b,
    wait_reg_mem                                 = 0x3c,
    indirect_buffer                              = 0x3f,
    copy_data                                    = 0x40,
    cp_dma                                       = 0x41,
    pfp_sync_me                                  = 0x42,
    surface_sync                                 = 0x43,
    me_initialize                                = 0x44,
    cond_write                                   = 0x45,
    event_write                                  = 0x46,
    event_write_eop                              = 0x47,
    event_write_eos                              = 0x48,
    release_mem                                  = 0x49,
    dma_data                                     = 0x50,
    context_reg_rmw                              = 0x51,
    gfx_cntx_update                              = 0x52,
    blk_cntx_update                              = 0x53,
    incr_updt_state                              = 0x55,
    acquire_mem                                  = 0x58,
    rewind                                       = 0x59,
    interrupt                                    = 0x5a,
    gen_pdepte                                   = 0x5b,
    indirect_buffer_pasid                        = 0x5c,
    prime_utcl2                                  = 0x5d,
    load_uconfig_reg                             = 0x5e,
    load_sh_reg                                  = 0x5f,
    load_config_reg                              = 0x60,
    load_context_reg                             = 0x61,
    load_compute_state                           = 0x62,
    load_sh_reg_index                            = 0x63,
    set_config_reg                               = 0x68,
    set_context_reg                              = 0x69,
    set_context_reg_index                        = 0x6a,
    set_vgpr_reg_di_multi                        = 0x71,
    set_sh_reg_di                                = 0x72,
    set_context_reg_indirect                     = 0x73,
    set_sh_reg_di_multi                          = 0x74,
    gfx_pipe_lock                                = 0x75,
    set_sh_reg                                   = 0x76,
    set_sh_reg_offset                            = 0x77,
    set_queue_reg                                = 0x78,
    set_uconfig_reg                              = 0x79,
    set_uconfig_reg_index                        = 0x7a,
    forward_header                               = 0x7c,
    scratch_ram_write                            = 0x7d,
    scratch_ram_read                             = 0x7e,
    load_const_ram                               = 0x80,
    write_const_ram                              = 0x81,
    dump_const_ram                               = 0x83,
    increment_ce_counter                         = 0x84,
    increment_de_counter                         = 0x85,
    wait_on_ce_counter                           = 0x86,
    wait_on_de_counter_diff                      = 0x88,
    switch_buffer                                = 0x8b,
    frame_control                                = 0x90,
    index_attributes_indirect                    = 0x91,
    wait_reg_mem64                               = 0x93,
    cond_preempt                                 = 0x94,
    hdp_flush                                    = 0x95,
    invalidate_tlbs                              = 0x98,
    dma_data_fill_multi                          = 0x9a,
    set_sh_reg_index                             = 0x9b,
    draw_indirect_count_multi                    = 0x9c,
    draw_index_indirect_count_multi              = 0x9d,
    dump_const_ram_offset                        = 0x9e,
    load_context_reg_index                       = 0x9f,
    set_resources                                = 0xa0,
    map_process                                  = 0xa1,
    map_queues                                   = 0xa2,
    unmap_queues                                 = 0xa3,
    query_status                                 = 0xa4,
    run_list                                     = 0xa5,
    map_process_vm                               = 0xa6,
    execute_indirect__execindirect               = 0xae,

    // dispatch_draw_preamble__gfx09                = 0x8c,
    // dispatch_draw__gfx09                         = 0x8d,
    // get_lod_stats__gfx09                         = 0x8e,
    // draw_multi_preamble__gfx09                   = 0x8f,
    // aql_packet__gfx09                            = 0x99,

    // draw_reserved0__gfx09_10                     = 0x4c,
    // draw_reserved1__gfx09_10                     = 0x4d,
    // draw_reserved2__gfx09_10                     = 0x4e,
    // draw_reserved3__gfx09_10                     = 0x4f,

    // dispatch_mesh_indirect_multi__gfx101         = 0x4c,
    // dispatch_taskmesh_gfx__gfx101                = 0x4d,
    // dispatch_draw_preamble__gfx101               = 0x8c,
    // dispatch_draw_preamble_ace__gfx101           = 0x8c,
    // dispatch_draw__gfx101                        = 0x8d,
    // dispatch_draw_ace__gfx101                    = 0x8d,
    // draw_multi_preamble__gfx101                  = 0x8f,
    // aql_packet__gfx101                           = 0x99,
    // dispatch_task_state_init__gfx101             = 0xa9,
    // dispatch_taskmesh_direct_ace__gfx101         = 0xaa,
    // dispatch_taskmesh_indirect_multi_ace__gfx101 = 0xad,
    // build_untyped_srd__gfx101                    = 0xaf,
    // perfmon_control__gfx103coreplus              = 0x54,
    // wait_for_write_confirm__gfx103plusexclusive  = 0x92,
    // context_push__gfx103plusexclusive            = 0xab,
    // context_pop__gfx103plusexclusive             = 0xac,
    // draw_multi_preamble__gfx103plusexclusive     = 0xfe,
    // aql_packet__gfx103plusexclusive              = 0xff,
    // load_uconfig_reg_index__gfx10plus            = 0x64,
    // clear_state__hasclearstate                   = 0x12,
    // preamble_cntl__hasclearstate                 = 0x4a,

    // dispatch_draw_preamble__nv21                 = 0x8c,
    // dispatch_draw_preamble_ace__nv21             = 0x8c,
    // dispatch_draw__nv21                          = 0x8d,
    // dispatch_draw_ace__nv21                      = 0x8d,
    // build_untyped_srd__nv21                      = 0xaf,

    // dispatch_draw_preamble__nv22                 = 0x8c,
    // dispatch_draw_preamble_ace__nv22             = 0x8c,
    // dispatch_draw__nv22                          = 0x8d,
    // dispatch_draw_ace__nv22                      = 0x8d,
    // build_untyped_srd__nv22                      = 0xaf,

    // dispatch_draw_preamble__nv23                 = 0x8c,
    // dispatch_draw_preamble_ace__nv23             = 0x8c,
    // dispatch_draw__nv23                          = 0x8d,
    // dispatch_draw_ace__nv23                      = 0x8d,
    // build_untyped_srd__nv23                      = 0xaf,

    // dispatch_draw_preamble__nv24                 = 0x8c,
    // dispatch_draw_preamble_ace__nv24             = 0x8c,
    // dispatch_draw__nv24                          = 0x8d,
    // dispatch_draw_ace__nv24                      = 0x8d,
    // build_untyped_srd__nv24                      = 0xaf,

    // build_untyped_srd__vega                      = 0xaf,

    // dispatch_mesh_indirect_multi__gfx11          = 0x4c,
    // dispatch_taskmesh_gfx__gfx11                 = 0x4d,
    // dispatch_mesh_direct__gfx11                  = 0x4e,
    // draw_reserved0__gfx11                        = 0x6b,
    // draw_reserved1__gfx11                        = 0x6c,
    // draw_reserved2__gfx11                        = 0x6d,
    // draw_reserved3__gfx11                        = 0x6e,
    // dispatch_task_state_init__gfx11              = 0xa9,
    // dispatch_taskmesh_direct_ace__gfx11          = 0xaa,
    // dispatch_taskmesh_indirect_multi_ace__gfx11  = 0xad,
    // build_untyped_srd__gfx11                     = 0xaf,
    // event_write_zpass__gfx11                     = 0xb1,
    // timestamp__gfx11                             = 0xb2,
    // marker__gfx11                                = 0xb7,
    // set_context_reg_pairs__gfx11                 = 0xb8,
    // set_context_reg_pairs_packed__gfx11          = 0xb9,
    // set_sh_reg_pairs__gfx11                      = 0xba,
    // set_sh_reg_pairs_packed__gfx11               = 0xbb,
    // set_sh_reg_pairs_packed_n__gfx11             = 0xbd,
};
// zig fmt: on
