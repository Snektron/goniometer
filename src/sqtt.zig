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
        asic_info,
        sqtt_desc,
        sqtt_data,
        api_info,
        reserved,
        queue_event_timings,
        clock_calibration,
        cpu_info,
        spm_db,
        code_object_database,
        code_object_loader_events,
        pso_correlation,
        instrumentation_table,
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
    padding: i32 = 0,
};

pub const CpuInfo = extern struct {
    header: ChunkHeader,
    vendor_id: [3 * 4]u8,
    processor_brand: [12 * 4]u8,
    _reserved: [2]u32 = .{ 0, 0 },
    cpu_timestamp_freq: u64,
    clock_speed: u32,
    num_logical_cores: u32,
    num_physical_cores: u32,
    system_ram_size: u32,
};

pub const AsicInfo = extern struct {
    pub const GpuType = enum(u32) { unknown = 0x0, integrated = 0x1, discrete = 0x2, virtual = 0x3 };

    pub const GfxipLevel = enum(u32) {
        none = 0x0,
        gfxip_6 = 0x1,
        gfxip_7 = 0x2,
        gfxip_8 = 0x3,
        gfxip_8_1 = 0x4,
        gfxip_9 = 0x5,
        gfxip_10_1 = 0x7,
        gfxip_10_3 = 0x9,
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
    flags: u64,
    trace_shader_core_clock: u64,
    trace_memory_clock: u64,
    device_id: i32,
    device_revision_id: i32,
    vgprs_per_simd: i32,
    sgprs_per_simd: i32,
    shader_engines: i32,
    compute_units_per_shader_engine: i32,
    simds_per_compute_unit: i32,
    wavefronts_per_simd: i32,
    minimum_vgpr_alloc: i32,
    vgpr_alloc_granularity: i32,
    minimum_sgpr_alloc: i32,
    sgpr_alloc_granularity: i32,
    hardware_contexts: i32,
    gpu_type: GpuType,
    gfxip_level: GfxipLevel,
    gpu_index: i32,
    gds_size: i32,
    gfs_per_shader_engine: i32,
    ce_ram_size: i32,
    ce_ram_size_graphics: i32,
    ce_ram_size_compute: i32,
    max_number_of_dedicated_cus: i32,
    vram_size: i64,
    vram_bus_width: i32,
    l2_cache_size: i32,
    l1_cache_size: i32,
    lds_size: i32,
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
    padding: [4]u8 = .{0} ** 4,
};

pub const ApiInfo = extern struct {
    pub const ApiType = enum(u32) {
        directx12,
        vulkan,
        generic,
        opencl,
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
        user_marker_data: extern struct {
            start: [256]u8,
            end: [256]u8,
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
