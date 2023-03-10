//! This file deals with the SQTT (RGP) file format.

pub const magic = 0x50303042;
pub const format_major = 1;
pub const format_minor = 5;

pub const FileHeader = extern struct {
    pub const Flags = packed struct(u32) {
        is_semaphore_queue_timing_etw: bool,
        no_queue_semaphore_timestamps: bool,
        _reserved: u30 = 0,
    };

    magic: u32,
    ver_major: u32,
    ver_minor: u32,
    flags: Flags,
    chunk_offset: i32,
    second: i32,
    minute: i32,
    hour: i32,
    day_in_month: i32,
    month: i32,
    year: i32,
    day_in_week: i32,
    day_in_year: i32,
    is_daylight_savings: i32,
};

pub const ChunkHeader = extern struct {
    pub const Type = enum(u8) {
        asic_info = 0,
        sqtt_desc = 1,
        sqtt_data = 2,
        api_info = 3,
        reserved = 4,
        queue_event_timings = 5,
        clock_calibration = 6,
        cpu_info = 7,
        spm_db = 8,
        code_object_database = 9,
        code_object_loader_events = 0xA,
        pso_correlation = 0xB,
        instrumentation_table = 0xC,
    };

    pub const Id = packed struct(u32) {
        chunk_type: Type,
        index: u8,
        _reserved: u16 = 0,
    };

    chunk_id: Id,
    ver_minor: u16,
    ver_major: u16,
    size_bytes: u32,
    _padding: i32 = 0,
};

pub const CpuInfo = extern struct {
    header: ChunkHeader,
    vendor_id: [12]u8,
    processor_brand: [48]u8,
    _reserved: [2]u32 = .{ 0, 0 },
    cpu_timestamp_freq: u64,
    clock_speed: u32,
    num_logical_cores: u32,
    num_physical_cores: u32,
    system_ram_size: u32,
};

pub const AsicInfo = extern struct {
    pub const GpuType = enum(u32) { unknown = 0x0, integrated = 0x1, discrete = 0x2, virtual = 0x3 };

    pub const Flags = packed struct(u64) {
        sc_packer_numbering: bool,
        ps1_event_tokens_enabled: bool,
        _reserved: u62 = 0,
    };

    pub const GfxipLevel = enum(u32) {
        none = 0x0,
        gfxip_6 = 0x1,
        gfxip_7 = 0x2,
        gfxip_8 = 0x3,
        gfxip_8_1 = 0x4,
        gfxip_9 = 0x5,
        gfxip_10_1 = 0x7,
        gfxip_10_3 = 0x9,
        gfxip_11 = 0xC,
    };

    pub const MemoryType = enum(u32) {
        unknown = 0x0,
        ddr = 0x1,
        ddr2 = 0x2,
        ddr3 = 0x3,
        ddr4 = 0x4,
        gddr3 = 0x10,
        gddr4 = 0x11,
        gddr5 = 0x12,
        gddr6 = 0x13,
        hbm = 0x20,
        hbm2 = 0x21,
        hbm3 = 0x22,
        lpddr4 = 0x30,
        lpddr5 = 0x31,
    };

    pub const gpu_name_max_size = 256;
    pub const max_num_se = 32;
    pub const sa_per_se = 2;

    header: ChunkHeader,
    flags: Flags,
    trace_shader_core_clock: u64,
    trace_memory_clock: u64,
    device_id: u32,
    device_revision_id: u32,
    vgprs_per_simd: u32,
    sgprs_per_simd: u32,
    shader_engines: u32,
    compute_units_per_shader_engine: u32,
    simds_per_compute_unit: u32,
    wavefronts_per_simd: u32,
    minimum_vgpr_alloc: u32,
    vgpr_alloc_granularity: u32,
    minimum_sgpr_alloc: u32,
    sgpr_alloc_granularity: u32,
    hardware_contexts: u32,
    gpu_type: GpuType,
    gfxip_level: GfxipLevel,
    gpu_index: u32,
    gds_size: u32,
    gds_per_shader_engine: u32,
    ce_ram_size: u32,
    ce_ram_size_graphics: u32,
    ce_ram_size_compute: u32,
    max_number_of_dedicated_cus: u32,
    vram_size: i64,
    vram_bus_width: u32,
    l2_cache_size: u32,
    l1_cache_size: u32,
    lds_size: u32,
    gpu_name: [gpu_name_max_size]u8,
    alu_per_clock: f32,
    texture_per_clock: f32,
    prims_per_clock: f32,
    pixels_per_clock: f32,
    gpu_timestamp_frequency: u64,
    max_shader_core_clock: u64,
    max_memory_clock: u64,
    memory_ops_per_clock: u32,
    memory_chip_type: MemoryType,
    lds_granularity: u32,
    cu_mask: [max_num_se][sa_per_se]u16,
    _reserved1: [128]u8 = .{0} ** 128,
    _padding: [4]u8 = .{0} ** 4,
};

pub const ApiInfo = extern struct {
    pub const ApiType = enum(u32) {
        directx12 = 0,
        vulkan = 1,
        generic = 2,
        opencl = 3,
        hip = 5,
    };

    pub const InstructionTraceMode = enum(u32) {
        disabled = 0x0,
        full_frame = 0x1,
        api_pso = 0x2,
    };

    pub const ProfilingMode = enum(u32) {
        present = 0x0,
        user_markers = 0x1,
        index = 0x2,
        tag = 0x3,
    };

    pub const ProfilingModeData = extern union {
        user_marking_profiling_data: extern struct {
            start: [256]u8,
            end: [256]u8,
        },
        index_profiling_data: extern struct {
            start: u32,
            end: u32,
        },
        tag_profiling_data: extern struct {
            begin_hi: u32,
            begin_lo: u32,
            end_hi: u32,
            end_lo: u32,
        },
    };

    pub const InstructionTraceData = extern union {
        api_pso_data: extern struct {
            api_pso_filter: u64,
        },
        shader_engine_filter: extern struct {
            mask: u32,
        },
    };

    header: ChunkHeader,
    api_type: ApiType,
    major_version: u16,
    minor_version: u16,
    profiling_mode: ProfilingMode,
    _reserved1: u32 = 0,
    profiling_mode_data: ProfilingModeData,
    instruction_trace_mode: InstructionTraceMode,
    _reserved2: u32 = 0,
    instruction_trace_data: InstructionTraceData,
};

pub const SqttDesc = extern struct {
    pub const Version = enum(c_int) {
        none = 0x0,
        @"2.2" = 0x5, // GFX8
        @"2.3" = 0x6, // GFX9
        @"2.4" = 0x7, // GFX10,
        @"3.2" = 0xb, // GFX11
    };

    header: ChunkHeader,
    shader_engine_index: u32,
    version: Version,
    instrumentation_spec_version: u16,
    instrumentation_api_version: u16,
    compute_unit_index: u32,
};

pub const SqttData = extern struct {
    header: ChunkHeader,
    offset: i32,
    size: u32,
};

pub const CodeObjectDatabase = extern struct {
    pub const Record = extern struct {
        record_size: u32,
    };

    header: ChunkHeader,
    offset: u32,
    flags: u32,
    size: u32,
    record_count: u32,
};

pub const ObjectLoaderEvents = extern struct {
    pub const EventType = enum(c_int) {
        load_to_gpu_memory = 0x0,
        unload_from_gpu_memory = 0x1,
    };

    pub const Record = extern struct {
        event_type: EventType,
        _reserved: u32 = 0,
        base_address: u64,
        code_object_hash: [2]u64,
        timestamp: u64,
    };

    header: ChunkHeader,
    offset: u32,
    flags: u32,
    record_size: u32,
    record_count: u32,
};

pub const PsoCorrelation = extern struct {
    pub const Record = extern struct {
        api_pso_hash: u64,
        internal_pipeline_hash: [2]u64,
        api_object_name: [64]u8,
    };

    header: ChunkHeader,
    offset: u32,
    flags: u32,
    record_size: u32,
    record_count: u32,
};

pub const QueueEventTimings = extern struct {
    pub const QueueType = enum(u8) {
        unknown = 0x0,
        universal = 0x1,
        compute = 0x2,
        dma = 0x3,
    };

    pub const EngineType = enum(u8) {
        unknown = 0x0,
        universal = 0x1,
        compute = 0x2,
        exclusive_compute = 0x3,
        dma = 0x4,
        high_priority_universal = 0x7,
        high_priority_compute = 0x8,
    };

    pub const QueueHardwareInfo = packed struct(u32) {
        queue_type: QueueType,
        engine_type: EngineType,
        _reserved: u16 = 0,
    };

    pub const QueueInfoRecord = extern struct {
        queue_id: u64,
        queue_context: u64,
        hardware_info: QueueHardwareInfo,
        _reserved: u32 = 0,
    };

    pub const QueueEventType = enum(u32) {
        cmdbuf_submit = 0x0,
        signal_semaphore = 0x1,
        wait_semaphore = 0x2,
        present = 0x3,
    };

    pub const QueueEventRecord = extern struct {
        event_type: QueueEventType,
        sqtt_cmdbuf_id: u32, // corresponds to marker.Event.cmdbuf_id, maybe.
        frame_index: u32,
        queue_info_index: u32,
        submit_sub_index: u32,
        api_id: u64,
        cpu_timestamp: u64,
        gpu_timestamp: [2]u64,
    };

    header: ChunkHeader,
    queue_info_record_count: u32,
    queue_info_record_size: u32,
    queue_event_record_count: u32,
    queue_event_record_size: u32,
};

pub const marker = struct {
    /// Note: the meaning of the marker identifier depends on the API that is being used. This type
    /// is specifically for HIP/OpenCL.
    pub const Identifier = enum(u4) {
        event = 0x0,
        cmdbuf_start = 0x1,
        cmdbuf_end = 0x2,
        barrier_start = 0x3,
        barrier_end = 0x4,
        user_event = 0x5,
        general_api = 0x6,
        sync = 0x7,
        present = 0x8,
        layout_transition = 0x9,
        render_pass = 0xA,
        reserved2 = 0xB,
        pipeline_bind = 0xC,
        reserved4 = 0xD,
        reserved5 = 0xE,
        reserved6 = 0xF,
    };

    pub const Event = packed struct(u96) {
        pub const Type = enum(u24) {
            cmd_nd_range_kernel = 0,
            cmd_scheduler = 1,
            cmd_copy_buffer = 2,
            cmd_copy_image_to_buffer = 3,
            cmd_copy_buffer_to_image = 4,
            cmd_fill_buffer = 5,
            cmd_copy_image = 6,
            cmd_fill_image = 7,
            cmd_pipeline_barrier = 8,
            internal_unknown = 26,
            invalid = 0xFF_FFFF,
        };

        identifier: Identifier = .event,
        extra_dwords: u3,
        api_type: Type,
        has_thread_dims: bool,

        cmdbuf_id: u20,
        vertex_offset_reg_idx: u4 = 0,
        instance_offset_reg_idx: u4 = 0,
        draw_index_reg_idx: u4 = 0,

        cmd_id: u32,
    };

    pub const EventWithDims = packed struct(u192) {
        event: Event,
        wgp_count_x: u32,
        wgp_count_y: u32,
        wgp_count_z: u32,
    };

    pub const BindPoint = enum(u1) {
        graphics = 0,
        compute = 1,
    };

    pub const PipelineBind = packed struct(u96) {
        identifier: Identifier = .pipeline_bind,
        extra_dwords: u3,
        bind_point: BindPoint,
        cmdbuf_id: u20,
        _reserved: u4 = 0,
        api_pso_hash: u64,
    };

    pub const UserEvent = packed struct(u32) {
        pub const Type = enum(u8) {
            trigger = 0x0,
            pop = 0x1,
            push = 0x2,
            object_name = 0x3,
            reserved1 = 0x4,
            reserved2 = 0x5,
            reserved3 = 0x6,
            reserved4 = 0x7,
        };

        identifier: Identifier = .user_event,
        extra_dwords: u8,
        data_type: Type,
        _reserved: u12 = 0,
    };

    pub const UserEventWithString = extern struct {
        user_event: UserEvent,
        str_len: u32,
        str_data: [1024 * 4]u8,
    };
};
