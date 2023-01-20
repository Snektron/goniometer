//! nice Zig-like bindings around HSA. Not strictly required, but looks nice.

const std = @import("std");
const AtomicOrder = std.builtin.AtomicOrder;

const pm4 = @import("pm4.zig");
const CmdBuf = @import("CmdBuf.zig");

pub const c = @cImport({
    @cInclude("hsa/hsa.h");
    @cInclude("hsa/hsa_ext_amd.h");
    @cInclude("hsa/hsa_ven_amd_aqlprofile.h");
    @cInclude("hsa/hsa_ven_amd_loader.h");
    @cInclude("hsa/amd_hsa_kernel_code.h");
});

pub const Status = c.hsa_status_t;
pub const Agent = c.hsa_agent_t;
pub const Queue = c.hsa_queue_t;
pub const Signal = c.hsa_signal_t;
pub const SignalValue = c.hsa_signal_value_t;
pub const Executable = c.hsa_executable_t;
pub const Symbol = c.hsa_executable_symbol_t;
pub const MemoryPool = c.hsa_amd_memory_pool_t;
pub const KernelDispatchPacket = c.hsa_kernel_dispatch_packet_t;
pub const LoadedCodeObject = c.hsa_loaded_code_object_t;

pub const AmdKernelCode = extern struct {
    pub const MachineKind = enum(u16) {
        undef = 0,
        amdgpu = 1,
        _,
    };

    pub const ComputePgmRsrc1 = packed struct(u32) {
        granulated_workitem_vgpr_count: u6,
        granulated_wavefront_sgpr_count: u4,
        priority: u2,
        float_round_mode_32: u2,
        float_found_mode_16_64: u2,
        float_denorm_mode_32: u2,
        float_denorm_mode_16_64: u2,
        priv: bool,
        enable_dx10_clamp: bool,
        debug_mode: bool,
        enable_ieee_mode: bool,
        bulky: bool,
        cdbg_user: bool,
        _reserved1: u6 = 0,
    };

    pub const ComputePgmRsrc2 = packed struct(u32) {
        enable_sgpr_private_segment_wave_byte_offset: bool,
        user_sgpr_count: u5,
        enable_trap_handler: bool,
        enable_sgpr_workgroup_id_x: bool,
        enable_sgpr_workgroup_id_y: bool,
        enable_sgpr_workgroup_id_z: bool,
        enable_sgpr_workgroup_id_info: bool,
        enable_vgpr_workitem_id: u2,
        enable_exception_address_watch: bool,
        enable_exception_memory_violation: bool,
        granulated_lds_size: u9,
        enable_exception_ieee_754_fp_invalid_operation: bool,
        enable_exception_fp_denormal_source: bool,
        enable_exception_ieee_754_fp_division_by_zero: bool,
        enable_exception_ieee_754_fp_overflow: bool,
        enable_exception_ieee_754_fp_underflow: bool,
        enable_exception_ieee_754_fp_inexact: bool,
        enable_exception_int_division_by_zero: bool,
        _reserved1: u1 = 0,
    };

    pub const KernelCodeProperties = packed struct(u32) {
        enable_sgpr_private_segment_buffer: bool,
        enable_sgpr_dispatch_ptr: bool,
        enable_sgpr_queue_ptr: bool,
        enable_sgpr_kernarg_segment_ptr: bool,
        enable_sgpr_dispatch_id: bool,
        enable_sgpr_flat_scratch_init: bool,
        enable_sgpr_private_segment_size: bool,
        enable_sgpr_grid_workgroup_count_x: bool,
        enable_sgpr_grid_workgroup_count_y: bool,
        enable_sgpr_grid_workgroup_count_z: bool,
        enable_wavefront32: bool,
        uses_dynamic_stack: bool,
        _reserved1: u4 = 0,
        enable_ordered_append_gds: bool,
        private_element_size: u2,
        is_ptr64: bool,
        is_dynamic_callstack: bool,
        is_debug_enabled: bool,
        is_xnack_enabled: bool,
        _reserved2: u9 = 0,
    };

    pub const EnabledControlDirectives = packed struct(u64) {
        enable_break_exceptions: bool,
        enable_detect_exceptions: bool,
        max_dynamic_group_size: bool,
        max_flat_grid_size: bool,
        required_dim: bool,
        required_grid_size: bool,
        required_workgroup_size: bool,
        require_no_partial_workgroups: bool,
        _reserved: u56 = 0,
    };

    pub const ControlDirectives = extern struct {
        enabled_control_directives: EnabledControlDirectives,
        enable_break_exceptions: u16,
        enable_detect_exceptions: u16,
        max_dynamic_group_size: u32,
        max_flat_grid_size: u64,
        max_flat_workgroup_size: u32,
        required_dim: u8,
        _reserved1: [3]u8,
        required_grid_size: [3]u64,
        required_workgroup_size: [3]u32,
        _reserved2: [60]u8,
    };

    ver_major: u32,
    ver_minor: u32,
    machine_kind: MachineKind,
    machine_ver_major: u16,
    machine_ver_minor: u16,
    machine_ver_stepping: u16,
    kernel_code_entry_byte_offset: i64,
    kernel_code_prefetch_byte_offset: i64,
    kernel_code_prefetch_byte_size: u64,
    max_scratch_backing_memory_byte_size: u64,
    compute_pgm_rsrc1: ComputePgmRsrc1,
    compute_pgm_rsrc2: ComputePgmRsrc2,
    kernel_code_properties: KernelCodeProperties,
    workitem_private_segment_byte_size: u32,
    workgroup_group_segment_byte_size: u32,
    gds_segment_byte_size: u32,
    kernarg_segment_byte_size: u64,
    workgroup_fbarrier_count: u32,
    wavefront_sgpr_count: u16,
    workitem_vgpr_count: u16,
    reserved_vgpr_first: u16,
    reserved_vgpr_count: u16,
    reserved_sgpr_first: u16,
    reserved_sgpr_count: u16,
    debug_wavefront_private_segment_offset_sgpr: u16,
    debug_private_segment_buffer_sgpr: u16,
    kernarg_segment_alignment: u8,
    group_segment_alignment: u8,
    private_segment_alignment: u8,
    wavefront_size: u8,
    call_convention: u32,
    _reserved1: [12]u8,
    runtime_loader_kernel_symbol: u64,
    control_directives: ControlDirectives align(64),
};

pub const DeviceType = enum(c_int) {
    cpu = c.HSA_DEVICE_TYPE_CPU,
    gpu = c.HSA_DEVICE_TYPE_GPU,
    _,
};

pub const Attribute = enum(c_int) {
    name = c.HSA_AGENT_INFO_NAME,
    vendor_name = c.HSA_AGENT_INFO_VENDOR_NAME,
    device_type = c.HSA_AGENT_INFO_DEVICE,
    node = c.HSA_AGENT_INFO_NODE,
    cache_size = c.HSA_AGENT_INFO_CACHE_SIZE,

    max_clock_freq = c.HSA_AMD_AGENT_INFO_MAX_CLOCK_FREQUENCY,
    product_name = c.HSA_AMD_AGENT_INFO_PRODUCT_NAME,
    num_shader_engines = c.HSA_AMD_AGENT_INFO_NUM_SHADER_ENGINES,
    timestamp_freq = c.HSA_AMD_AGENT_INFO_TIMESTAMP_FREQUENCY,
    max_memory_freq = c.HSA_AMD_AGENT_INFO_MEMORY_MAX_FREQUENCY,
    asic_revision = c.HSA_AMD_AGENT_INFO_ASIC_REVISION,
    num_compute_units = c.HSA_AMD_AGENT_INFO_COMPUTE_UNIT_COUNT,
    num_simds_per_cu = c.HSA_AMD_AGENT_INFO_NUM_SIMDS_PER_CU,
    max_waves_per_cu = c.HSA_AMD_AGENT_INFO_MAX_WAVES_PER_CU,
    memory_width = c.HSA_AMD_AGENT_INFO_MEMORY_WIDTH,
    chip_id = c.HSA_AMD_AGENT_INFO_CHIP_ID,

    pub fn Type(comptime self: Attribute) type {
        return switch (self) {
            .name => [64]u8,
            .vendor_name => [64]u8,
            .device_type => DeviceType,
            .node => u32,
            .cache_size => [4]u32,

            .max_clock_freq => u32,
            .product_name => [64]u8,
            .num_shader_engines => u32,
            .timestamp_freq => u64,
            .max_memory_freq => u32,
            .asic_revision => u32,
            .num_compute_units => u32,
            .num_simds_per_cu => u32,
            .max_waves_per_cu => u32,
            .memory_width => u32,
            .chip_id => u32,
        };
    }
};

pub const SymbolKind = enum(c_int) {
    variable,
    kernel,
    indirect_function,
};

pub const SymbolAttribute = enum(c_int) {
    kind = c.HSA_EXECUTABLE_SYMBOL_INFO_TYPE,
    name_len = c.HSA_EXECUTABLE_SYMBOL_INFO_NAME_LENGTH,
    name = c.HSA_EXECUTABLE_SYMBOL_INFO_NAME,
    kernel_object = c.HSA_EXECUTABLE_SYMBOL_INFO_KERNEL_OBJECT,

    pub fn Type(comptime self: SymbolAttribute) type {
        return switch (self) {
            .kind => SymbolKind,
            .name_len => u32,
            .name => unreachable, // Requires allocation
            .kernel_object => u64,
        };
    }
};

pub const QueueType32 = enum(u32) {
    multi = c.HSA_QUEUE_TYPE_MULTI,
    single = c.HSA_QUEUE_TYPE_SINGLE,
    cooperative = c.HSA_QUEUE_TYPE_COOPERATIVE,
};

pub const SignalCondition = enum(c_uint) {
    eq = c.HSA_SIGNAL_CONDITION_EQ,
    ne = c.HSA_SIGNAL_CONDITION_NE,
    lt = c.HSA_SIGNAL_CONDITION_LT,
};

pub const WaitState = enum(c_uint) {
    blocked = c.HSA_WAIT_STATE_BLOCKED,
    active = c.HSA_WAIT_STATE_ACTIVE,
};

pub const Segment = enum(c_int) {
    global = c.HSA_AMD_SEGMENT_GLOBAL,
    readonly = c.HSA_AMD_SEGMENT_READONLY,
    private = c.HSA_AMD_SEGMENT_PRIVATE,
    group = c.HSA_AMD_SEGMENT_GROUP,
    _,
};

pub const MemoryPoolAttribute = enum(c_int) {
    segment = c.HSA_AMD_MEMORY_POOL_INFO_SEGMENT,
    runtime_alloc_allowed = c.HSA_AMD_MEMORY_POOL_INFO_RUNTIME_ALLOC_ALLOWED,

    pub fn Type(comptime self: MemoryPoolAttribute) type {
        return switch (self) {
            .segment => Segment,
            .runtime_alloc_allowed => bool,
        };
    }
};

pub const LoadedCodeObjectStorageType = enum(c_int) {
    none = 0,
    file = 1,
    memory = 2,
};

pub const LoadedCodeObjectAttribute = enum(c_int) {
    storage_type = c.HSA_VEN_AMD_LOADER_LOADED_CODE_OBJECT_INFO_CODE_OBJECT_STORAGE_TYPE,
    memory_base = c.HSA_VEN_AMD_LOADER_LOADED_CODE_OBJECT_INFO_CODE_OBJECT_STORAGE_MEMORY_BASE,
    memory_size = c.HSA_VEN_AMD_LOADER_LOADED_CODE_OBJECT_INFO_CODE_OBJECT_STORAGE_MEMORY_SIZE,
    storage_file = c.HSA_VEN_AMD_LOADER_LOADED_CODE_OBJECT_INFO_CODE_OBJECT_STORAGE_FILE,
    uri_len = c.HSA_VEN_AMD_LOADER_LOADED_CODE_OBJECT_INFO_URI_LENGTH,
    uri = c.HSA_VEN_AMD_LOADER_LOADED_CODE_OBJECT_INFO_URI,
    load_delta = c.HSA_VEN_AMD_LOADER_LOADED_CODE_OBJECT_INFO_LOAD_DELTA,

    pub fn Type(comptime self: LoadedCodeObjectAttribute) type {
        return switch (self) {
            .storage_type => LoadedCodeObjectStorageType,
            .memory_base => [*]u8,
            .memory_size => u64,
            .storage_file => std.os.fd_t,
            .uri_len => u32,
            .uri => unreachable, // requires allocation
            .load_delta => i64,
        };
    }
};

pub const Extension = enum(c_int) {
    finalizer = 0,
    images = 1,
    performance_counters = 2,
    profiling_events = 3,
    amd_profiler = 0x200,
    amd_loader = 0x201,
    amd_aqlprofile = 0x202,
};

/// HSA headers dont define a generic packet type :/
pub const Packet = extern struct {
    pub const alignment = 64;

    pub const Type = enum(u8) {
        vendor_specific = c.HSA_PACKET_TYPE_VENDOR_SPECIFIC,
        invalid = c.HSA_PACKET_TYPE_INVALID,
        kernel_dispatch = c.HSA_PACKET_TYPE_KERNEL_DISPATCH,
        barrier_and = c.HSA_PACKET_TYPE_BARRIER_AND,
        agent_dispatch = c.HSA_PACKET_TYPE_AGENT_DISPATCH,
        barrier_or = c.HSA_PACKET_TYPE_BARRIER_OR,

        pub fn PacketType(comptime self: Type) type {
            return switch (self) {
                .kernel_dispatch => KernelDispatchPacket,
                else => unreachable, // Add if required.
            };
        }
    };

    pub const Header = packed struct(u16) {
        packet_type: Type,
        barrier: u1,
        acquire_fence_scope: u2,
        release_fence_scope: u2,
        _reserved: u3 = 0,
    };

    comptime {
        std.debug.assert(@sizeOf(Packet) == alignment);
    }

    header: Header,
    body: [31]u16,

    pub fn cast(self: *align(alignment) Packet, comptime ty: Type) ?*align(alignment) ty.PacketType() {
        if (self.header.packet_type == ty) {
            return @ptrCast(*ty.PacketType(), self);
        }
        return null;
    }
};

/// This is a HSA packet that can be used to make the GPU execute a PM4 command stream
/// instead of the regular aqlqueue command stream.
/// Note: This packet is different for GFX <= 8. Check AMDPAL for its structure
/// in that situation.
pub const Pm4IndirectBufferPacket = extern struct {
    comptime {
        std.debug.assert(@sizeOf(Pm4IndirectBufferPacket) == Packet.alignment);
    }

    const pm4_size = 4;

    /// Sub-type of this packet
    pub const Type = enum(u16) {
        // PM4 'indirect_buffer' command. Only the indirect buffer command may
        // be placed in the pm4 data, it seems.
        pm4_ib = 0x1,
    };

    /// HSA packet header, set to 0 for vendor-specific packet.
    header: Packet.Header,
    /// Vendor-specific-packet header.
    ven_hdr: Type,
    /// The actual PM4 command for this packet. It seems that there can only be one
    /// type of command here, corresponding to the ven_hdr, of which currently only
    /// the IB command is known.
    pm4: [pm4_size]pm4.Word,
    /// The amount of words that remain
    dw_remain: u32,
    /// Padding
    _reserved: [8]u32 = .{0} ** 8,
    /// Signal that probably gets ringed if this packet has been finished executing or something.
    completion_signal: Signal,

    /// Initialze a PM4 packet. `signal` is optional.
    pub fn init(ib: []const pm4.Word, signal: ?Signal) Pm4IndirectBufferPacket {
        var packet = Pm4IndirectBufferPacket{
            .header = .{
                .packet_type = .vendor_specific,
                .barrier = 0,
                .acquire_fence_scope = 0,
                .release_fence_scope = 0,
            },
            .ven_hdr = .pm4_ib,
            .pm4 = .{0} ** pm4_size,
            .dw_remain = 0xA,
            .completion_signal = signal orelse .{ .handle = 0 },
        };
        var cmdbuf = CmdBuf{
            .cap = pm4_size,
            .buf = &packet.pm4,
        };
        cmdbuf.indirectBuffer(ib);
        return packet;
    }

    pub fn asHsaPacket(self: *const Pm4IndirectBufferPacket) *const Packet {
        return @ptrCast(*const Packet, self);
    }
};

/// Get the packet buffer for an HSA queue.
pub fn queuePacketBuffer(queue: *Queue) []align(Packet.alignment) Packet {
    return @ptrCast(
        [*]align(Packet.alignment) Packet,
        @alignCast(Packet.alignment, queue.base_address.?),
    )[0..queue.size];
}

/// This struct represents a handle to HSA. This struct holds the function pointers that
/// we care about, as well as Zig-like wrapper functions.
pub const Instance = struct {
    /// Core functionality.
    agent_get_info: *const @TypeOf(c.hsa_agent_get_info),
    iterate_agents: *const @TypeOf(c.hsa_iterate_agents),
    queue_create: *const @TypeOf(c.hsa_queue_create),
    queue_destroy: *const @TypeOf(c.hsa_queue_destroy),
    queue_load_read_index_relaxed: *const @TypeOf(c.hsa_queue_load_read_index_relaxed),
    queue_load_read_index_scacquire: *const @TypeOf(c.hsa_queue_load_read_index_scacquire),
    queue_load_write_index_relaxed: *const @TypeOf(c.hsa_queue_load_write_index_relaxed),
    queue_load_write_index_scacquire: *const @TypeOf(c.hsa_queue_load_write_index_scacquire),
    queue_store_write_index_relaxed: *const @TypeOf(c.hsa_queue_store_write_index_relaxed),
    queue_store_write_index_screlease: *const @TypeOf(c.hsa_queue_store_write_index_screlease),
    queue_add_write_index_relaxed: *const @TypeOf(c.hsa_queue_add_write_index_relaxed),
    queue_add_write_index_scacq_screl: *const @TypeOf(c.hsa_queue_add_write_index_scacq_screl),
    queue_add_write_index_scacquire: *const @TypeOf(c.hsa_queue_add_write_index_scacquire),
    queue_add_write_index_screlease: *const @TypeOf(c.hsa_queue_add_write_index_screlease),
    signal_create: *const @TypeOf(c.hsa_signal_create),
    signal_destroy: *const @TypeOf(c.hsa_signal_destroy),
    signal_store_relaxed: *const @TypeOf(c.hsa_signal_store_relaxed),
    signal_store_screlease: *const @TypeOf(c.hsa_signal_store_screlease),
    signal_wait_scacquire: *const @TypeOf(c.hsa_signal_wait_scacquire),
    executable_freeze: *const @TypeOf(c.hsa_executable_freeze),
    executable_destroy: *const @TypeOf(c.hsa_executable_destroy),
    executable_iterate_symbols: *const @TypeOf(c.hsa_executable_iterate_symbols),
    executable_symbol_get_info: *const @TypeOf(c.hsa_executable_symbol_get_info),

    /// AMD-specific functionality.
    amd_agent_iterate_memory_pools: *const @TypeOf(c.hsa_amd_agent_iterate_memory_pools),
    amd_agents_allow_access: *const @TypeOf(c.hsa_amd_agents_allow_access),
    amd_memory_pool_allocate: *const @TypeOf(c.hsa_amd_memory_pool_allocate),
    amd_memory_pool_free: *const @TypeOf(c.hsa_amd_memory_pool_free),
    amd_memory_pool_get_info: *const @TypeOf(c.hsa_amd_memory_pool_get_info),
    amd_profiling_set_profiler_enabled: *const @TypeOf(c.hsa_amd_profiling_set_profiler_enabled),
    amd_loader_query_host_address: *const @TypeOf(c.hsa_ven_amd_loader_query_host_address),
    amd_loader_executable_iterate_loaded_code_objects: *const @TypeOf(c.hsa_ven_amd_loader_executable_iterate_loaded_code_objects),
    amd_loader_loaded_code_object_get_info: *const @TypeOf(c.hsa_ven_amd_loader_loaded_code_object_get_info),

    pub fn init(api_table: *const ApiTable) Instance {
        var loader_api: c.hsa_ven_amd_loader_1_03_pfn_t = undefined;
        switch (api_table.core.system_get_major_extension_table(
            c.HSA_EXTENSION_AMD_LOADER,
            1,
            @sizeOf(c.hsa_ven_amd_loader_1_03_pfn_t),
            &loader_api,
        )) {
            c.HSA_STATUS_SUCCESS => {},
            c.HSA_STATUS_ERROR_NOT_INITIALIZED => unreachable,
            c.HSA_STATUS_ERROR_INVALID_ARGUMENT => unreachable,
            else => unreachable,
        }

        return .{
            .agent_get_info = api_table.core.agent_get_info,
            .iterate_agents = api_table.core.iterate_agents,
            .queue_create = api_table.core.queue_create,
            .queue_destroy = api_table.core.queue_destroy,
            .queue_load_read_index_relaxed = api_table.core.queue_load_read_index_relaxed,
            .queue_load_read_index_scacquire = api_table.core.queue_load_read_index_scacquire,
            .queue_load_write_index_relaxed = api_table.core.queue_load_write_index_relaxed,
            .queue_load_write_index_scacquire = api_table.core.queue_load_write_index_scacquire,
            .queue_store_write_index_relaxed = api_table.core.queue_store_write_index_relaxed,
            .queue_store_write_index_screlease = api_table.core.queue_store_write_index_screlease,
            .queue_add_write_index_relaxed = api_table.core.queue_add_write_index_relaxed,
            .queue_add_write_index_scacq_screl = api_table.core.queue_add_write_index_scacq_screl,
            .queue_add_write_index_scacquire = api_table.core.queue_add_write_index_scacquire,
            .queue_add_write_index_screlease = api_table.core.queue_add_write_index_screlease,
            .signal_create = api_table.core.signal_create,
            .signal_destroy = api_table.core.signal_destroy,
            .signal_store_relaxed = api_table.core.signal_store_relaxed,
            .signal_store_screlease = api_table.core.signal_store_screlease,
            .signal_wait_scacquire = api_table.core.signal_wait_scacquire,
            .executable_freeze = api_table.core.executable_freeze,
            .executable_destroy = api_table.core.executable_destroy,
            .executable_iterate_symbols = api_table.core.executable_iterate_symbols,
            .executable_symbol_get_info = api_table.core.executable_symbol_get_info,

            .amd_agent_iterate_memory_pools = api_table.amd_ext.agent_iterate_memory_pools,
            .amd_agents_allow_access = api_table.amd_ext.agents_allow_access,
            .amd_memory_pool_allocate = api_table.amd_ext.memory_pool_allocate,
            .amd_memory_pool_free = api_table.amd_ext.memory_pool_free,
            .amd_memory_pool_get_info = api_table.amd_ext.memory_pool_get_info,
            .amd_profiling_set_profiler_enabled = api_table.amd_ext.profiling_set_profiler_enabled,
            .amd_loader_query_host_address = loader_api.hsa_ven_amd_loader_query_host_address.?,
            .amd_loader_executable_iterate_loaded_code_objects = loader_api.hsa_ven_amd_loader_executable_iterate_loaded_code_objects.?,
            .amd_loader_loaded_code_object_get_info = loader_api.hsa_ven_amd_loader_loaded_code_object_get_info.?,
        };
    }

    // Custom functionality //

    /// Submit a generic packet to a HSA queue. This function may block until
    /// there is enough room for the packet.
    pub fn submit(
        self: *const Instance,
        queue: *Queue,
        packet: *const Packet,
    ) void {
        const write_index = self.queueAddWriteIndex(queue, 1, .AcqRel);

        // Busy loop until there is space.
        // TODO: Maybe this can be improved or something?
        while (write_index - self.queueLoadReadIndex(queue, .Monotonic) >= queue.size) {
            continue;
        }

        const slot_index = @intCast(u32, write_index % queue.size);
        const slot = &queuePacketBuffer(queue)[slot_index];

        // AQL packets have an 'invalid' header, which indicates that there is no packet at this
        // slot index yet - we want to overwrite that last, so that the packet is not read before
        // it is completely written.
        const packet_bytes = std.mem.asBytes(packet);
        const slot_bytes = std.mem.asBytes(slot);
        std.mem.copy(u8, slot_bytes[2..], packet_bytes[2..]);
        // Write the packet header atomically.
        @atomicStore(u16, @ptrCast(*u16, &slot.header), @bitCast(u16, packet.header), .Release);

        // Finally, ring the doorbell to notify the agent of the updated packet.
        self.signalStore(queue.doorbell_signal, @intCast(SignalValue, write_index), .Monotonic);
    }

    // Wrapped API functionality //

    pub fn getAgentInfo(
        self: *const Instance,
        agent: Agent,
        comptime attribute: Attribute,
    ) attribute.Type() {
        var value: attribute.Type() = undefined;
        return switch (self.agent_get_info(
            agent,
            @enumToInt(attribute),
            @ptrCast(*anyopaque, &value),
        )) {
            c.HSA_STATUS_SUCCESS => value,
            c.HSA_STATUS_ERROR_NOT_INITIALIZED => unreachable,
            c.HSA_STATUS_ERROR_INVALID_AGENT => unreachable,
            c.HSA_STATUS_ERROR_INVALID_ARGUMENT => unreachable, // Something is wrong with Attribute
            else => unreachable, // Undocumented error.
        };
    }

    fn IterateAgents(comptime Context: type, comptime callback: anytype) type {
        return @TypeOf(callback(@as(Context, undefined), @as(Agent, undefined)));
    }

    pub fn iterateAgents(
        self: *const Instance,
        context: anytype,
        /// should be of type `callback: fn(context: @TypeOf(context), agent: Agent) !?T`
        /// Iteration is interrupted if ?T holds a value.
        comptime callback: anytype,
    ) IterateAgents(@TypeOf(context), callback) {
        const Context = @TypeOf(context);
        const Result = IterateAgents(Context, callback);
        const S = struct {
            context: Context,
            result: Result,

            fn cbk(agent: Agent, data: ?*anyopaque) callconv(.C) Status {
                const s = @ptrCast(*@This(), @alignCast(@alignOf(@This()), data.?));
                s.result = callback(s.context, agent);
                const result = s.result catch return c.HSA_STATUS_ERROR;
                if (result != null) {
                    return c.HSA_STATUS_INFO_BREAK;
                }
                return c.HSA_STATUS_SUCCESS;
            }
        };
        var ctx = S{
            .context = context,
            .result = null,
        };
        _ = self.iterate_agents(S.cbk, &ctx);
        return ctx.result;
    }

    pub fn createQueue(
        self: *const Instance,
        agent: Agent,
        size: u32,
        queue_type: QueueType32,
        callback: ?*const fn (status: Status, source: *Queue, data: ?*anyopaque) callconv(.C) void, // TODO: wrap
        data: ?*anyopaque,
        private_segment_size: u32,
        group_segment_size: u32,
    ) !*Queue {
        var queue: [*c]Queue = undefined;
        return switch (self.queue_create(
            agent,
            size,
            @enumToInt(queue_type),
            @ptrCast(?*const fn (Status, [*c]Queue, data: ?*anyopaque) callconv(.C) void, callback),
            data,
            private_segment_size,
            group_segment_size,
            &queue,
        )) {
            c.HSA_STATUS_SUCCESS => queue,
            c.HSA_STATUS_ERROR_OUT_OF_RESOURCES => error.OutOfResources,
            c.HSA_STATUS_ERROR_INVALID_QUEUE_CREATION => error.InvalidQueueCreation,
            c.HSA_STATUS_ERROR_NOT_INITIALIZED => unreachable,
            c.HSA_STATUS_ERROR_INVALID_AGENT => unreachable,
            c.HSA_STATUS_ERROR_INVALID_ARGUMENT => unreachable, // Precondition violated.
            else => unreachable, // Undocumented error.
        };
    }

    pub fn destroyQueue(
        self: *const Instance,
        queue: *Queue,
    ) void {
        switch (self.queue_destroy(queue)) {
            c.HSA_STATUS_SUCCESS => {},
            c.HSA_STATUS_ERROR_INVALID_QUEUE => unreachable,
            c.HSA_STATUS_ERROR_INVALID_ARGUMENT => unreachable,
            else => unreachable, // Undocumented error.
        }
    }

    pub fn queueLoadReadIndex(
        self: *const Instance,
        queue: *const Queue,
        comptime ordering: AtomicOrder,
    ) u64 {
        const func = comptime switch (ordering) {
            .Monotonic => self.queue_load_read_index_relaxed,
            .Acquire => self.queue_load_read_index_scacquire,
            else => unreachable, // Invalid memory ordering.
        };
        return func(queue);
    }

    pub fn queueLoadWriteIndex(
        self: *const Instance,
        queue: *const Queue,
        comptime ordering: AtomicOrder,
    ) u64 {
        const func = comptime switch (ordering) {
            .Monotonic => self.queue_load_write_index_relaxed,
            .Acquire => self.queue_load_write_index_scacquire,
            else => unreachable, // Invalid memory ordering.
        };
        return func(queue);
    }

    pub fn queueStoreWriteIndex(
        self: *const Instance,
        queue: *const Queue,
        value: u64,
        comptime ordering: AtomicOrder,
    ) void {
        const func = comptime switch (ordering) {
            .Monotonic => self.queue_store_write_index_relaxed,
            .Release => self.queue_store_write_index_screlease,
            else => unreachable, // Invalid memory ordering.
        };
        func(queue, value);
    }

    pub fn queueAddWriteIndex(
        self: *const Instance,
        queue: *const Queue,
        value: u64,
        comptime ordering: AtomicOrder,
    ) u64 {
        const func = comptime switch (ordering) {
            .Monotonic => self.queue_add_write_index_relaxed,
            .AcqRel => self.queue_add_write_index_scacq_screl,
            .Acquire => self.queue_add_write_index_scacquire,
            .Release => self.queue_add_write_index_screlease,
            else => unreachable, // Invalid memory ordering.
        };
        return func(queue, value);
    }

    pub fn createSignal(
        self: *const Instance,
        initial_value: SignalValue,
        consumers: []const Agent,
    ) !Signal {
        var signal: Signal = undefined;
        return switch (self.signal_create(
            initial_value,
            @intCast(u32, consumers.len),
            if (consumers.len == 0) null else consumers.ptr,
            &signal,
        )) {
            c.HSA_STATUS_SUCCESS => signal,
            c.HSA_STATUS_ERROR_OUT_OF_RESOURCES => error.OutOfResources,
            c.HSA_STATUS_ERROR_NOT_INITIALIZED => unreachable,
            c.HSA_STATUS_ERROR_INVALID_ARGUMENT => unreachable,
            else => unreachable, //  Undocumented error.
        };
    }

    pub fn destroySignal(self: *const Instance, signal: Signal) void {
        switch (self.signal_destroy(signal)) {
            c.HSA_STATUS_SUCCESS => {},
            c.HSA_STATUS_ERROR_NOT_INITIALIZED => unreachable,
            c.HSA_STATUS_ERROR_INVALID_SIGNAL => unreachable,
            c.HSA_STATUS_ERROR_INVALID_ARGUMENT => unreachable,
            else => unreachable, //  Undocumented error.
        }
    }

    pub fn signalStore(
        self: *const Instance,
        signal: Signal,
        value: SignalValue,
        comptime ordering: AtomicOrder,
    ) void {
        const func = comptime switch (ordering) {
            .Monotonic => self.signal_store_relaxed,
            .Release => self.signal_store_screlease,
            else => unreachable, // Invalid memory ordering.
        };
        func(signal, value);
    }

    pub fn signalWait(
        self: *const Instance,
        signal: Signal,
        condition: SignalCondition,
        compare_value: SignalValue,
        timeout_hint: u64,
        wait_state_hint: WaitState,
        comptime ordering: AtomicOrder,
    ) SignalValue {
        const func = comptime switch (ordering) {
            .Monotonic => unreachable, // TODO: add
            .Acquire => self.signal_wait_scacquire,
            else => unreachable, // Invalid memory ordering.
        };
        return func(signal, @enumToInt(condition), compare_value, timeout_hint, @enumToInt(wait_state_hint));
    }

    fn freezeExecutable(self: *const Instance, exe: Executable, options: [*:0]const u8) !void {
        return switch (self.executable_freeze(
            exe,
            options,
        )) {
            c.HSA_STATUS_SUCCESS => {},
            c.HSA_STATUS_ERROR_NOT_INITIALIZED => unreachable,
            c.HSA_STATUS_ERROR_INVALID_EXECUTABLE => unreachable,
            c.HSA_STATUS_ERROR_VARIABLE_UNDEFINED => error.VariableUndefined,
            c.HSA_STATUS_ERROR_FROZEN_EXECUTABLE => error.FrozenExecutable,
            else => unreachable, // Undocumented error
        };
    }

    fn destroyExecutable(self: *const Instance, exe: Executable) void {
        return switch (self.executable_destroy(exe)) {
            c.HSA_STATUS_SUCCESS => {},
            c.HSA_STATUS_ERROR_NOT_INITIALIZED => unreachable,
            c.HSA_STATUS_ERROR_INVALID_EXECUTABLE => unreachable,
            else => unreachable, // Undocumented error
        };
    }

    fn IterateSymbols(comptime Context: type, comptime callback: anytype) type {
        return @TypeOf(callback(@as(Context, undefined), @as(Executable, undefined), @as(Symbol, undefined)));
    }

    pub fn iterateSymbols(
        self: *const Instance,
        exe: Executable,
        context: anytype,
        /// should be of type `callback: fn(context: @TypeOf(context), Executable, Symbol) !?T`
        /// Iteration is interrupted if ?T holds a value.
        comptime callback: anytype,
    ) IterateSymbols(@TypeOf(context), callback) {
        const Context = @TypeOf(context);
        const Result = IterateSymbols(Context, callback);
        const S = struct {
            context: Context,
            result: Result,

            fn cbk(exe_: Executable, sym: Symbol, data: ?*anyopaque) callconv(.C) Status {
                const s = @ptrCast(*@This(), @alignCast(@alignOf(@This()), data.?));
                s.result = callback(s.context, exe_, sym);
                const result = s.result catch return c.HSA_STATUS_ERROR;
                if (result != null) {
                    return c.HSA_STATUS_INFO_BREAK;
                }
                return c.HSA_STATUS_SUCCESS;
            }
        };
        var ctx = S{
            .context = context,
            .result = undefined,
        };
        _ = self.executable_iterate_symbols(exe, S.cbk, &ctx);
        return ctx.result;
    }

    pub fn getSymbolInfo(
        self: *const Instance,
        sym: Symbol,
        comptime attribute: SymbolAttribute,
    ) attribute.Type() {
        var value: attribute.Type() = undefined;
        return switch (self.executable_symbol_get_info(
            sym,
            @enumToInt(attribute),
            @ptrCast(*anyopaque, &value),
        )) {
            c.HSA_STATUS_SUCCESS => value,
            c.HSA_STATUS_ERROR_NOT_INITIALIZED => unreachable,
            c.HSA_STATUS_ERROR_INVALID_AGENT => unreachable,
            c.HSA_STATUS_ERROR_INVALID_MEMORY_POOL => unreachable,
            c.HSA_STATUS_ERROR_INVALID_ARGUMENT => unreachable, // Something is wrong with Attribute
            else => unreachable, // Undocumented error.
        };
    }

    pub fn getSymbolName(
        self: *const Instance,
        sym: Symbol,
        allocator: std.mem.Allocator,
    ) ![]const u8 {
        const len = self.getSymbolInfo(sym, .name_len);
        const result = try allocator.alloc(u8, len);
        return switch (self.executable_symbol_get_info(
            sym,
            @enumToInt(SymbolAttribute.name),
            result.ptr,
        )) {
            c.HSA_STATUS_SUCCESS => result,
            c.HSA_STATUS_ERROR_NOT_INITIALIZED => unreachable,
            c.HSA_STATUS_ERROR_INVALID_EXECUTABLE => unreachable,
            c.HSA_STATUS_ERROR_INVALID_ARGUMENT => unreachable, // Something is wrong with Attribute
            else => unreachable, // Undocumented error.
        };
    }

    fn IterateMemoryPools(comptime Context: type, comptime callback: anytype) type {
        return @TypeOf(callback(@as(Context, undefined), @as(MemoryPool, undefined)));
    }

    pub fn iterateMemoryPools(
        self: *const Instance,
        agent: Agent,
        context: anytype,
        /// should be of type `callback: fn(context: @TypeOf(context), pool: MemoryPool) !?T
        /// Iteration is interrupted if ?T holds a value.
        comptime callback: anytype,
    ) IterateMemoryPools(@TypeOf(context), callback) {
        const Context = @TypeOf(context);
        const Result = IterateMemoryPools(Context, callback);
        const S = struct {
            context: Context,
            result: Result,

            fn cbk(pool: MemoryPool, data: ?*anyopaque) callconv(.C) Status {
                const s = @ptrCast(*@This(), @alignCast(@alignOf(@This()), data.?));
                s.result = callback(s.context, pool);
                const result = s.result catch return c.HSA_STATUS_ERROR;
                if (result != null) {
                    return c.HSA_STATUS_INFO_BREAK;
                }
                return c.HSA_STATUS_SUCCESS;
            }
        };
        var ctx = S{
            .context = context,
            .result = null,
        };
        _ = self.amd_agent_iterate_memory_pools(agent, S.cbk, &ctx);
        return ctx.result;
    }

    pub fn agentsAllowAccess(
        self: *const Instance,
        ptr: *anyopaque,
        agents: []const Agent,
    ) void {
        return switch (self.amd_agents_allow_access(
            @intCast(u32, agents.len),
            agents.ptr,
            null,
            ptr,
        )) {
            c.HSA_STATUS_SUCCESS => {},
            c.HSA_STATUS_ERROR_NOT_INITIALIZED => unreachable,
            c.HSA_STATUS_ERROR_INVALID_ARGUMENT => unreachable,
            else => unreachable, // Undocumented error.
        };
    }

    pub fn memoryPoolAllocate(
        self: *const Instance,
        comptime T: type,
        pool: MemoryPool,
        size: usize,
    ) ![]T {
        var ptr: [*]T = undefined;
        return switch (self.amd_memory_pool_allocate(
            pool,
            size * @sizeOf(T),
            0,
            @ptrCast(*?*anyopaque, &ptr),
        )) {
            c.HSA_STATUS_SUCCESS => ptr[0..size],
            c.HSA_STATUS_ERROR_OUT_OF_RESOURCES => error.OutOfResources,
            c.HSA_STATUS_ERROR_INVALID_MEMORY_POOL => unreachable,
            c.HSA_STATUS_ERROR_INVALID_ALLOCATION => unreachable,
            c.HSA_STATUS_ERROR_INVALID_ARGUMENT => unreachable,
            else => unreachable, // Undocumented error.
        };
    }

    pub fn memoryPoolFree(
        self: *const Instance,
        buf: anytype,
    ) void {
        const ptr = switch (@typeInfo(@TypeOf(buf)).Pointer.size) {
            .Slice => buf.ptr,
            else => buf,
        };
        switch (self.amd_memory_pool_free(ptr)) {
            c.HSA_STATUS_SUCCESS => {},
            c.HSA_STATUS_ERROR_NOT_INITIALIZED => unreachable,
            else => unreachable, // Undocumented error.
        }
    }

    pub fn getMemoryPoolInfo(
        self: *const Instance,
        pool: MemoryPool,
        comptime attribute: MemoryPoolAttribute,
    ) attribute.Type() {
        var value: attribute.Type() = undefined;
        return switch (self.amd_memory_pool_get_info(
            pool,
            @enumToInt(attribute),
            @ptrCast(*anyopaque, &value),
        )) {
            c.HSA_STATUS_SUCCESS => value,
            c.HSA_STATUS_ERROR_NOT_INITIALIZED => unreachable,
            c.HSA_STATUS_ERROR_INVALID_AGENT => unreachable,
            c.HSA_STATUS_ERROR_INVALID_MEMORY_POOL => unreachable,
            c.HSA_STATUS_ERROR_INVALID_ARGUMENT => unreachable, // Something is wrong with Attribute
            else => unreachable, // Undocumented error.
        };
    }

    pub fn loaderQueryHostAddress(
        self: *const Instance,
        comptime T: type,
        device_addr: *const T,
    ) *const T {
        var host_addr: *const T = undefined;
        return switch (self.amd_loader_query_host_address(
            device_addr,
            @ptrCast(*?*const anyopaque, &host_addr),
        )) {
            c.HSA_STATUS_SUCCESS => host_addr,
            c.HSA_STATUS_ERROR_NOT_INITIALIZED => unreachable,
            c.HSA_STATUS_ERROR_INVALID_ARGUMENT => unreachable, // Invalid `device_addr`
            else => unreachable, // Undocumented error
        };
    }

    fn IterateCodeObjects(comptime Context: type, comptime callback: anytype) type {
        return @TypeOf(callback(@as(Context, undefined), @as(Executable, undefined), @as(LoadedCodeObject, undefined)));
    }

    pub fn iterateLoadedCodeObjects(
        self: *const Instance,
        exe: Executable,
        context: anytype,
        /// should be of type `callback: fn(context: @TypeOf(context), exe: Executable, code_object: LoadedCodeObject) !?T`
        /// Iteration is interrupted if ?T holds a value.
        comptime callback: anytype,
    ) IterateCodeObjects(@TypeOf(context), callback) {
        const Context = @TypeOf(context);
        const Result = IterateCodeObjects(Context, callback);
        const S = struct {
            context: Context,
            result: Result,

            fn cbk(exe_: Executable, code_object: LoadedCodeObject, data: ?*anyopaque) callconv(.C) Status {
                const s = @ptrCast(*@This(), @alignCast(@alignOf(@This()), data.?));
                s.result = callback(s.context, exe_, code_object);
                const result = s.result catch return c.HSA_STATUS_ERROR;
                if (result != null) {
                    return c.HSA_STATUS_INFO_BREAK;
                }
                return c.HSA_STATUS_SUCCESS;
            }
        };
        var ctx = S{
            .context = context,
            .result = null,
        };
        _ = self.amd_loader_executable_iterate_loaded_code_objects(exe, S.cbk, &ctx);
        return ctx.result;
    }

    pub fn getLoadedCodeObjectInfo(
        self: *const Instance,
        co: LoadedCodeObject,
        comptime attribute: LoadedCodeObjectAttribute,
    ) attribute.Type() {
        var value: attribute.Type() = undefined;
        return switch (self.amd_loader_loaded_code_object_get_info(
            co,
            @enumToInt(attribute),
            @ptrCast(*anyopaque, &value),
        )) {
            c.HSA_STATUS_SUCCESS => value,
            c.HSA_STATUS_ERROR_NOT_INITIALIZED => unreachable,
            c.HSA_STATUS_ERROR_INVALID_EXECUTABLE => unreachable,
            c.HSA_STATUS_ERROR_INVALID_ARGUMENT => unreachable, // Something is wrong with Attribute
            else => unreachable, // Undocumented error.
        };
    }

    pub fn getLoadedCodeObjectUri(
        self: *const Instance,
        co: LoadedCodeObject,
        allocator: std.mem.Allocator,
    ) ![]const u8 {
        const len = self.getLoadedCodeObjectInfo(co, .uri_len);
        const result = try allocator.alloc(u8, len);
        return switch (self.amd_loader_loaded_code_object_get_info(
            co,
            @enumToInt(LoadedCodeObjectAttribute.uri),
            @ptrCast(*anyopaque, result.ptr),
        )) {
            c.HSA_STATUS_SUCCESS => result,
            c.HSA_STATUS_ERROR_NOT_INITIALIZED => unreachable,
            c.HSA_STATUS_ERROR_INVALID_EXECUTABLE => unreachable,
            c.HSA_STATUS_ERROR_INVALID_ARGUMENT => unreachable, // Something is wrong with Attribute
            else => unreachable, // Undocumented error.
        };
    }
};

pub const Error = error{
    Generic,
    InvalidArgument,
    InvalidQueueCreation,
    InvalidAllocation,
    InvalidAgent,
    InvalidRegion,
    InvalidSignal,
    InvalidQueue,
    OutOfResources,
    InvalidPacketFormat,
    ResourceFree,
    NotInitialized,
    RefcountOverflow,
    IncompatibleArguments,
    InvalidIndex,
    InvalidIsa,
    InvalidIsaName,
    InvalidCodeObject,
    InvalidExecutable,
    FrozenExecutable,
    InvalidSymbolName,
    VariableAlreadyDefined,
    VariableUndefined,
    Exception,
    InvalidCodeSymbol,
    InvalidExecutableSymbol,
    InvalidFile,
    InvalidCodeObjectReader,
    InvalidCache,
    InvalidWavefront,
    InvalidSignalGroup,
    InvalidRuntimeState,
    Fatal,
};

/// Convert a Zig error to a HSA error.
pub fn toStatus(err: (Error || error{OutOfMemory})) c.hsa_status_t {
    return switch (err) {
        error.Generic => c.HSA_STATUS_ERROR,
        error.InvalidArgument => c.HSA_STATUS_ERROR_INVALID_ARGUMENT,
        error.InvalidQueueCreation => c.HSA_STATUS_ERROR_INVALID_QUEUE_CREATION,
        error.InvalidAllocation => c.HSA_STATUS_ERROR_INVALID_ALLOCATION,
        error.InvalidAgent => c.HSA_STATUS_ERROR_INVALID_AGENT,
        error.InvalidRegion => c.HSA_STATUS_ERROR_INVALID_REGION,
        error.InvalidSignal => c.HSA_STATUS_ERROR_INVALID_SIGNAL,
        error.InvalidQueue => c.HSA_STATUS_ERROR_INVALID_QUEUE,
        error.OutOfResources => c.HSA_STATUS_ERROR_OUT_OF_RESOURCES,
        error.InvalidPacketFormat => c.HSA_STATUS_ERROR_INVALID_PACKET_FORMAT,
        error.ResourceFree => c.HSA_STATUS_ERROR_RESOURCE_FREE,
        error.NotInitialized => c.HSA_STATUS_ERROR_NOT_INITIALIZED,
        error.RefcountOverflow => c.HSA_STATUS_ERROR_REFCOUNT_OVERFLOW,
        error.IncompatibleArguments => c.HSA_STATUS_ERROR_INCOMPATIBLE_ARGUMENTS,
        error.InvalidIndex => c.HSA_STATUS_ERROR_INVALID_INDEX,
        error.InvalidIsa => c.HSA_STATUS_ERROR_INVALID_ISA,
        error.InvalidIsaName => c.HSA_STATUS_ERROR_INVALID_ISA_NAME,
        error.InvalidCodeObject => c.HSA_STATUS_ERROR_INVALID_CODE_OBJECT,
        error.InvalidExecutable => c.HSA_STATUS_ERROR_INVALID_EXECUTABLE,
        error.FrozenExecutable => c.HSA_STATUS_ERROR_FROZEN_EXECUTABLE,
        error.InvalidSymbolName => c.HSA_STATUS_ERROR_INVALID_SYMBOL_NAME,
        error.VariableAlreadyDefined => c.HSA_STATUS_ERROR_VARIABLE_ALREADY_DEFINED,
        error.VariableUndefined => c.HSA_STATUS_ERROR_VARIABLE_UNDEFINED,
        error.Exception => c.HSA_STATUS_ERROR_EXCEPTION,
        error.InvalidCodeSymbol => c.HSA_STATUS_ERROR_INVALID_CODE_SYMBOL,
        error.InvalidExecutableSymbol => c.HSA_STATUS_ERROR_INVALID_EXECUTABLE_SYMBOL,
        error.InvalidFile => c.HSA_STATUS_ERROR_INVALID_FILE,
        error.InvalidCodeObjectReader => c.HSA_STATUS_ERROR_INVALID_CODE_OBJECT_READER,
        error.InvalidCache => c.HSA_STATUS_ERROR_INVALID_CACHE,
        error.InvalidWavefront => c.HSA_STATUS_ERROR_INVALID_WAVEFRONT,
        error.InvalidSignalGroup => c.HSA_STATUS_ERROR_INVALID_SIGNAL_GROUP,
        error.InvalidRuntimeState => c.HSA_STATUS_ERROR_INVALID_RUNTIME_STATE,
        error.Fatal => c.HSA_STATUS_ERROR_FATAL,

        // Also handle some common errors
        error.OutOfMemory => c.HSA_STATUS_ERROR_OUT_OF_RESOURCES,
    };
}

pub const ApiTableVersion = extern struct {
    major_id: u32,
    minor_id: u32,
    step_id: u32,
    reserved: u32 = 0,
};

pub const CoreApiTable = extern struct {
    version: ApiTableVersion,

    init: *const @TypeOf(c.hsa_init),
    shut_down: *const @TypeOf(c.hsa_shut_down),
    system_get_info: *const @TypeOf(c.hsa_system_get_info),
    system_extension_supported: *const @TypeOf(c.hsa_system_extension_supported),
    system_get_extension_table: *const @TypeOf(c.hsa_system_get_extension_table),
    iterate_agents: *const @TypeOf(c.hsa_iterate_agents),
    agent_get_info: *const @TypeOf(c.hsa_agent_get_info),
    queue_create: *const @TypeOf(c.hsa_queue_create),
    soft_queue_create: *const @TypeOf(c.hsa_soft_queue_create),
    queue_destroy: *const @TypeOf(c.hsa_queue_destroy),
    queue_inactivate: *const @TypeOf(c.hsa_queue_inactivate),
    queue_load_read_index_scacquire: *const @TypeOf(c.hsa_queue_load_read_index_scacquire),
    queue_load_read_index_relaxed: *const @TypeOf(c.hsa_queue_load_read_index_relaxed),
    queue_load_write_index_scacquire: *const @TypeOf(c.hsa_queue_load_write_index_scacquire),
    queue_load_write_index_relaxed: *const @TypeOf(c.hsa_queue_load_write_index_relaxed),
    queue_store_write_index_relaxed: *const @TypeOf(c.hsa_queue_store_write_index_relaxed),
    queue_store_write_index_screlease: *const @TypeOf(c.hsa_queue_store_write_index_screlease),
    queue_cas_write_index_scacq_screl: *const @TypeOf(c.hsa_queue_cas_write_index_scacq_screl),
    queue_cas_write_index_scacquire: *const @TypeOf(c.hsa_queue_cas_write_index_scacquire),
    queue_cas_write_index_relaxed: *const @TypeOf(c.hsa_queue_cas_write_index_relaxed),
    queue_cas_write_index_screlease: *const @TypeOf(c.hsa_queue_cas_write_index_screlease),
    queue_add_write_index_scacq_screl: *const @TypeOf(c.hsa_queue_add_write_index_scacq_screl),
    queue_add_write_index_scacquire: *const @TypeOf(c.hsa_queue_add_write_index_scacquire),
    queue_add_write_index_relaxed: *const @TypeOf(c.hsa_queue_add_write_index_relaxed),
    queue_add_write_index_screlease: *const @TypeOf(c.hsa_queue_add_write_index_screlease),
    queue_store_read_index_relaxed: *const @TypeOf(c.hsa_queue_store_read_index_relaxed),
    queue_store_read_index_screlease: *const @TypeOf(c.hsa_queue_store_read_index_screlease),
    agent_iterate_regions: *const @TypeOf(c.hsa_agent_iterate_regions),
    region_get_info: *const @TypeOf(c.hsa_region_get_info),
    agent_get_exception_policies: *const @TypeOf(c.hsa_agent_get_exception_policies),
    agent_extension_supported: *const @TypeOf(c.hsa_agent_extension_supported),
    memory_register: *const @TypeOf(c.hsa_memory_register),
    memory_deregister: *const @TypeOf(c.hsa_memory_deregister),
    memory_allocate: *const @TypeOf(c.hsa_memory_allocate),
    memory_free: *const @TypeOf(c.hsa_memory_free),
    memory_copy: *const @TypeOf(c.hsa_memory_copy),
    memory_assign_agent: *const @TypeOf(c.hsa_memory_assign_agent),
    signal_create: *const @TypeOf(c.hsa_signal_create),
    signal_destroy: *const @TypeOf(c.hsa_signal_destroy),
    signal_load_relaxed: *const @TypeOf(c.hsa_signal_load_relaxed),
    signal_load_scacquire: *const @TypeOf(c.hsa_signal_load_scacquire),
    signal_store_relaxed: *const @TypeOf(c.hsa_signal_store_relaxed),
    signal_store_screlease: *const @TypeOf(c.hsa_signal_store_screlease),
    signal_wait_relaxed: *const @TypeOf(c.hsa_signal_wait_relaxed),
    signal_wait_scacquire: *const @TypeOf(c.hsa_signal_wait_scacquire),
    signal_and_relaxed: *const @TypeOf(c.hsa_signal_and_relaxed),
    signal_and_scacquire: *const @TypeOf(c.hsa_signal_and_scacquire),
    signal_and_screlease: *const @TypeOf(c.hsa_signal_and_screlease),
    signal_and_scacq_screl: *const @TypeOf(c.hsa_signal_and_scacq_screl),
    signal_or_relaxed: *const @TypeOf(c.hsa_signal_or_relaxed),
    signal_or_scacquire: *const @TypeOf(c.hsa_signal_or_scacquire),
    signal_or_screlease: *const @TypeOf(c.hsa_signal_or_screlease),
    signal_or_scacq_screl: *const @TypeOf(c.hsa_signal_or_scacq_screl),
    signal_xor_relaxed: *const @TypeOf(c.hsa_signal_xor_relaxed),
    signal_xor_scacquire: *const @TypeOf(c.hsa_signal_xor_scacquire),
    signal_xor_screlease: *const @TypeOf(c.hsa_signal_xor_screlease),
    signal_xor_scacq_screl: *const @TypeOf(c.hsa_signal_xor_scacq_screl),
    signal_exchange_relaxed: *const @TypeOf(c.hsa_signal_exchange_relaxed),
    signal_exchange_scacquire: *const @TypeOf(c.hsa_signal_exchange_scacquire),
    signal_exchange_screlease: *const @TypeOf(c.hsa_signal_exchange_screlease),
    signal_exchange_scacq_screl: *const @TypeOf(c.hsa_signal_exchange_scacq_screl),
    signal_add_relaxed: *const @TypeOf(c.hsa_signal_add_relaxed),
    signal_add_scacquire: *const @TypeOf(c.hsa_signal_add_scacquire),
    signal_add_screlease: *const @TypeOf(c.hsa_signal_add_screlease),
    signal_add_scacq_screl: *const @TypeOf(c.hsa_signal_add_scacq_screl),
    signal_subtract_relaxed: *const @TypeOf(c.hsa_signal_subtract_relaxed),
    signal_subtract_scacquire: *const @TypeOf(c.hsa_signal_subtract_scacquire),
    signal_subtract_screlease: *const @TypeOf(c.hsa_signal_subtract_screlease),
    signal_subtract_scacq_screl: *const @TypeOf(c.hsa_signal_subtract_scacq_screl),
    signal_cas_relaxed: *const @TypeOf(c.hsa_signal_cas_relaxed),
    signal_cas_scacquire: *const @TypeOf(c.hsa_signal_cas_scacquire),
    signal_cas_screlease: *const @TypeOf(c.hsa_signal_cas_screlease),
    signal_cas_scacq_screl: *const @TypeOf(c.hsa_signal_cas_scacq_screl),

    //===--- Instruction Set Architecture -----------------------------------===//

    isa_from_name: *const @TypeOf(c.hsa_isa_from_name),
    // Deprecated since v1.1.
    isa_get_info: *const @TypeOf(c.hsa_isa_get_info),
    // Deprecated since v1.1.
    isa_compatible: *const @TypeOf(c.hsa_isa_compatible),

    //===--- Code Objects (deprecated) --------------------------------------===//

    // Deprecated since v1.1.
    code_object_serialize: *const @TypeOf(c.hsa_code_object_serialize),
    // Deprecated since v1.1.
    code_object_deserialize: *const @TypeOf(c.hsa_code_object_deserialize),
    // Deprecated since v1.1.
    code_object_destroy: *const @TypeOf(c.hsa_code_object_destroy),
    // Deprecated since v1.1.
    code_object_get_info: *const @TypeOf(c.hsa_code_object_get_info),
    // Deprecated since v1.1.
    code_object_get_symbol: *const @TypeOf(c.hsa_code_object_get_symbol),
    // Deprecated since v1.1.
    code_symbol_get_info: *const @TypeOf(c.hsa_code_symbol_get_info),
    // Deprecated since v1.1.
    code_object_iterate_symbols: *const @TypeOf(c.hsa_code_object_iterate_symbols),

    //===--- Executable -----------------------------------------------------===//

    // Deprecated since v1.1.
    executable_create: *const @TypeOf(c.hsa_executable_create),
    executable_destroy: *const @TypeOf(c.hsa_executable_destroy),
    // Deprecated since v1.1.
    executable_load_code_object: *const @TypeOf(c.hsa_executable_load_code_object),
    executable_freeze: *const @TypeOf(c.hsa_executable_freeze),
    executable_get_info: *const @TypeOf(c.hsa_executable_get_info),
    executable_global_variable_define: *const @TypeOf(c.hsa_executable_global_variable_define),
    executable_agent_global_variable_define: *const @TypeOf(c.hsa_executable_agent_global_variable_define),
    executable_readonly_variable_define: *const @TypeOf(c.hsa_executable_readonly_variable_define),
    executable_validate: *const @TypeOf(c.hsa_executable_validate),
    // Deprecated since v1.1.
    executable_get_symbol: *const @TypeOf(c.hsa_executable_get_symbol),
    executable_symbol_get_info: *const @TypeOf(c.hsa_executable_symbol_get_info),
    // Deprecated since v1.1.
    executable_iterate_symbols: *const @TypeOf(c.hsa_executable_iterate_symbols),

    //===--- Runtime Notifications ------------------------------------------===//

    status_string: *const @TypeOf(c.hsa_status_string),

    // Start HSA v1.1 additions
    extension_get_name: *const @TypeOf(c.hsa_extension_get_name),
    system_major_extension_supported: *const @TypeOf(c.hsa_system_major_extension_supported),
    system_get_major_extension_table: *const @TypeOf(c.hsa_system_get_major_extension_table),
    agent_major_extension_supported: *const @TypeOf(c.hsa_agent_major_extension_supported),
    cache_get_info: *const @TypeOf(c.hsa_cache_get_info),
    agent_iterate_caches: *const @TypeOf(c.hsa_agent_iterate_caches),
    signal_silent_store_relaxed: *const @TypeOf(c.hsa_signal_silent_store_relaxed),
    signal_silent_store_screlease: *const @TypeOf(c.hsa_signal_silent_store_screlease),
    signal_group_create: *const @TypeOf(c.hsa_signal_group_create),
    signal_group_destroy: *const @TypeOf(c.hsa_signal_group_destroy),
    signal_group_wait_any_scacquire: *const @TypeOf(c.hsa_signal_group_wait_any_scacquire),
    signal_group_wait_any_relaxed: *const @TypeOf(c.hsa_signal_group_wait_any_relaxed),

    //===--- Instruction Set Architecture - HSA v1.1 additions --------------===//

    agent_iterate_isas: *const @TypeOf(c.hsa_agent_iterate_isas),
    isa_get_info_alt: *const @TypeOf(c.hsa_isa_get_info_alt),
    isa_get_exception_policies: *const @TypeOf(c.hsa_isa_get_exception_policies),
    isa_get_round_method: *const @TypeOf(c.hsa_isa_get_round_method),
    wavefront_get_info: *const @TypeOf(c.hsa_wavefront_get_info),
    isa_iterate_wavefronts: *const @TypeOf(c.hsa_isa_iterate_wavefronts),

    //===--- Code Objects (deprecated) - HSA v1.1 additions -----------------===//

    // Deprecated since v1.1.
    code_object_get_symbol_from_name: *const @TypeOf(c.hsa_code_object_get_symbol_from_name),

    //===--- Executable - HSA v1.1 additions --------------------------------===//

    code_object_reader_create_from_file: *const @TypeOf(c.hsa_code_object_reader_create_from_file),
    code_object_reader_create_from_memory: *const @TypeOf(c.hsa_code_object_reader_create_from_memory),
    code_object_reader_destroy: *const @TypeOf(c.hsa_code_object_reader_destroy),
    executable_create_alt: *const @TypeOf(c.hsa_executable_create_alt),
    executable_load_program_code_object: *const @TypeOf(c.hsa_executable_load_program_code_object),
    executable_load_agent_code_object: *const @TypeOf(c.hsa_executable_load_agent_code_object),
    executable_validate_alt: *const @TypeOf(c.hsa_executable_validate_alt),
    executable_get_symbol_by_name: *const @TypeOf(c.hsa_executable_get_symbol_by_name),
    executable_iterate_agent_symbols: *const @TypeOf(c.hsa_executable_iterate_agent_symbols),
    executable_iterate_program_symbols: *const @TypeOf(c.hsa_executable_iterate_program_symbols),
};

pub const AmdExtTable = extern struct {
    version: ApiTableVersion,
    coherency_get_type: *const @TypeOf(c.hsa_amd_coherency_get_type),
    coherency_set_type: *const @TypeOf(c.hsa_amd_coherency_set_type),
    profiling_set_profiler_enabled: *const @TypeOf(c.hsa_amd_profiling_set_profiler_enabled),
    profiling_async_copy_enable: *const @TypeOf(c.hsa_amd_profiling_async_copy_enable),
    profiling_get_dispatch_time: *const @TypeOf(c.hsa_amd_profiling_get_dispatch_time),
    profiling_get_async_copy_time: *const @TypeOf(c.hsa_amd_profiling_get_async_copy_time),
    profiling_convert_tick_to_system_domain: *const @TypeOf(c.hsa_amd_profiling_convert_tick_to_system_domain),
    signal_async_handler: *const @TypeOf(c.hsa_amd_signal_async_handler),
    async_function: *const @TypeOf(c.hsa_amd_async_function),
    signal_wait_any: *const @TypeOf(c.hsa_amd_signal_wait_any),
    queue_cu_set_mask: *const @TypeOf(c.hsa_amd_queue_cu_set_mask),
    memory_pool_get_info: *const @TypeOf(c.hsa_amd_memory_pool_get_info),
    agent_iterate_memory_pools: *const @TypeOf(c.hsa_amd_agent_iterate_memory_pools),
    memory_pool_allocate: *const @TypeOf(c.hsa_amd_memory_pool_allocate),
    memory_pool_free: *const @TypeOf(c.hsa_amd_memory_pool_free),
    memory_async_copy: *const @TypeOf(c.hsa_amd_memory_async_copy),
    agent_memory_pool_get_info: *const @TypeOf(c.hsa_amd_agent_memory_pool_get_info),
    agents_allow_access: *const @TypeOf(c.hsa_amd_agents_allow_access),
    memory_pool_can_migrate: *const @TypeOf(c.hsa_amd_memory_pool_can_migrate),
    memory_migrate: *const @TypeOf(c.hsa_amd_memory_migrate),
    memory_lock: *const @TypeOf(c.hsa_amd_memory_lock),
    memory_unlock: *const @TypeOf(c.hsa_amd_memory_unlock),
    memory_fill: *const @TypeOf(c.hsa_amd_memory_fill),
    interop_map_buffer: *const @TypeOf(c.hsa_amd_interop_map_buffer),
    interop_unmap_buffer: *const @TypeOf(c.hsa_amd_interop_unmap_buffer),
    image_create: *const @TypeOf(c.hsa_amd_image_create),
    pointer_info: *const @TypeOf(c.hsa_amd_pointer_info),
    pointer_info_set_userdata: *const @TypeOf(c.hsa_amd_pointer_info_set_userdata),
    ipc_memory_create: *const @TypeOf(c.hsa_amd_ipc_memory_create),
    ipc_memory_attach: *const @TypeOf(c.hsa_amd_ipc_memory_attach),
    ipc_memory_detach: *const @TypeOf(c.hsa_amd_ipc_memory_detach),
    signal_create: *const @TypeOf(c.hsa_amd_signal_create),
    ipc_signal_create: *const @TypeOf(c.hsa_amd_ipc_signal_create),
    ipc_signal_attach: *const @TypeOf(c.hsa_amd_ipc_signal_attach),
    register_system_event_handler: *const @TypeOf(c.hsa_amd_register_system_event_handler),
    queue_intercept_create: *const anyopaque, // defined in hsa_api_trace.h, translate if needed
    queue_intercept_register: *const anyopaque,
    queue_set_priority: *const @TypeOf(c.hsa_amd_queue_set_priority),
    memory_async_copy_rect: *const @TypeOf(c.hsa_amd_memory_async_copy_rect),
    runtime_queue_create_register: *const anyopaque,
    memory_lock_to_pool: *const @TypeOf(c.hsa_amd_memory_lock_to_pool),
    register_deallocation_callback: *const @TypeOf(c.hsa_amd_register_deallocation_callback),
    deregister_deallocation_callback: *const @TypeOf(c.hsa_amd_deregister_deallocation_callback),
    signal_value_pointer: *const @TypeOf(c.hsa_amd_signal_value_pointer),
    svm_attributes_set: *const @TypeOf(c.hsa_amd_svm_attributes_set),
    svm_attributes_get: *const @TypeOf(c.hsa_amd_svm_attributes_get),
    svm_prefetch_async: *const @TypeOf(c.hsa_amd_svm_prefetch_async),
    queue_cu_get_mask: *const @TypeOf(c.hsa_amd_queue_cu_get_mask),
};

// To add as needed
pub const FinalizerExtTable = anyopaque;
pub const ImageExtTable = anyopaque;

pub const ApiTable = extern struct {
    version: ApiTableVersion,
    core: *CoreApiTable,
    amd_ext: *AmdExtTable,
    finalizer_ext: *FinalizerExtTable,
    image_ext: *ImageExtTable,
};
