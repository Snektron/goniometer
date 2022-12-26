//! nice Zig-like bindings around HSA. Not strictly required, but looks nice.

const std = @import("std");
const AtomicOrder = std.builtin.AtomicOrder;

pub const c = @cImport({
    @cInclude("hsa/hsa.h");
    @cInclude("hsa/hsa_ext_amd.h");
    @cInclude("hsa/hsa_ven_amd_aqlprofile.h");
});

pub const Status = c.hsa_status_t;
pub const Agent = c.hsa_agent_t;
pub const Queue = c.hsa_queue_t;
pub const Signal = c.hsa_signal_t;
pub const SignalValue = c.hsa_signal_value_t;
pub const MemoryPool = c.hsa_amd_memory_pool_t;

pub const DeviceType = enum(c_int) {
    cpu = c.HSA_DEVICE_TYPE_CPU,
    gpu = c.HSA_DEVICE_TYPE_GPU,
    _,
};

pub const Attribute = enum(c_int) {
    name = c.HSA_AGENT_INFO_NAME,
    device_type = c.HSA_AGENT_INFO_DEVICE,
    num_shader_engines = c.HSA_AMD_AGENT_INFO_NUM_SHADER_ENGINES,

    pub fn Type(comptime self: Attribute) type {
        return switch (self) {
            .name => [64]u8,
            .device_type => DeviceType,
            .num_shader_engines => u32,
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
};

pub const IterationAction = enum {
    @"break",
    @"continue",
};

/// This struct represents a handle to HSA. This struct holds the function pointers that
/// we care about, as well as Zig-like wrapper functions.
pub const Instance = struct {
    /// Core functionality.
    agent_get_info: *const @TypeOf(c.hsa_agent_get_info),
    iterate_agents: *const @TypeOf(c.hsa_iterate_agents),
    queue_add_write_index_relaxed: *const @TypeOf(c.hsa_queue_add_write_index_relaxed),
    queue_add_write_index_scacq_screl: *const @TypeOf(c.hsa_queue_add_write_index_scacq_screl),
    queue_create: *const @TypeOf(c.hsa_queue_create),
    queue_destroy: *const @TypeOf(c.hsa_queue_destroy),
    queue_load_read_index_relaxed: *const @TypeOf(c.hsa_queue_load_read_index_relaxed),
    queue_load_write_index_relaxed: *const @TypeOf(c.hsa_queue_load_write_index_relaxed),
    queue_store_write_index_relaxed: *const @TypeOf(c.hsa_queue_store_write_index_relaxed),
    signal_create: *const @TypeOf(c.hsa_signal_create),
    signal_destroy: *const @TypeOf(c.hsa_signal_destroy),
    signal_store_relaxed: *const @TypeOf(c.hsa_signal_store_relaxed),
    signal_wait_scacquire: *const @TypeOf(c.hsa_signal_wait_scacquire),

    /// AMD-specific functionality.
    amd_agent_iterate_memory_pools: *const @TypeOf(c.hsa_amd_agent_iterate_memory_pools),
    amd_agents_allow_access: *const @TypeOf(c.hsa_amd_agents_allow_access),
    amd_memory_pool_allocate: *const @TypeOf(c.hsa_amd_memory_pool_allocate),
    amd_memory_pool_free: *const @TypeOf(c.hsa_amd_memory_pool_free),
    amd_memory_pool_get_info: *const @TypeOf(c.hsa_amd_memory_pool_get_info),

    pub fn init(api_table: *const ApiTable) Instance {
        return .{
            .agent_get_info = api_table.core.agent_get_info,
            .iterate_agents = api_table.core.iterate_agents,
            .queue_add_write_index_relaxed = api_table.core.queue_add_write_index_relaxed,
            .queue_add_write_index_scacq_screl = api_table.core.queue_add_write_index_scacq_screl,
            .queue_create = api_table.core.queue_create,
            .queue_destroy = api_table.core.queue_destroy,
            .queue_load_read_index_relaxed = api_table.core.queue_load_read_index_relaxed,
            .queue_load_write_index_relaxed = api_table.core.queue_load_write_index_relaxed,
            .queue_store_write_index_relaxed = api_table.core.queue_store_write_index_relaxed,
            .signal_create = api_table.core.signal_create,
            .signal_destroy = api_table.core.signal_destroy,
            .signal_store_relaxed = api_table.core.signal_store_relaxed,
            .signal_wait_scacquire = api_table.core.signal_wait_scacquire,

            .amd_agent_iterate_memory_pools = api_table.amd_ext.agent_iterate_memory_pools,
            .amd_agents_allow_access = api_table.amd_ext.agents_allow_access,
            .amd_memory_pool_allocate = api_table.amd_ext.memory_pool_allocate,
            .amd_memory_pool_free = api_table.amd_ext.memory_pool_free,
            .amd_memory_pool_get_info = api_table.amd_ext.memory_pool_get_info,
        };
    }

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
            .result = undefined,
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
        queue: *Queue,
        comptime ordering: AtomicOrder,
    ) u64 {
        const func = comptime switch (ordering) {
            .Monotonic => self.queue_load_read_index_relaxed,
            .Acquire => unreachable, // TODO: add
            else => unreachable, // Invalid memory ordering.
        };
        return func(queue);
    }

    pub fn queueLoadWriteIndex(
        self: *const Instance,
        queue: *Queue,
        comptime ordering: AtomicOrder,
    ) u64 {
        const func = comptime switch (ordering) {
            .Monotonic => self.queue_load_write_index_relaxed,
            .Acquire => unreachable, // TODO: add
            else => unreachable, // Invalid memory ordering.
        };
        return func(queue);
    }

    pub fn queueStoreWriteIndex(
        self: *const Instance,
        queue: *Queue,
        value: u64,
        comptime ordering: AtomicOrder,
    ) void {
        const func = comptime switch (ordering) {
            .Monotonic => self.queue_store_write_index_relaxed,
            .Release => unreachable, // TODO: add
            else => unreachable, // Invalid memory ordering.
        };
        func(queue, value);
    }

    pub fn queueAddWriteIndex(
        self: *const Instance,
        queue: *Queue,
        value: u64,
        comptime ordering: AtomicOrder,
    ) u64 {
        const func = comptime switch (ordering) {
            .Monotonic => self.queue_add_write_index_relaxed,
            .AcqRel => self.queue_add_write_index_scacq_screl,
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
            .Release => unreachable, // TODO: add
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
            .result = undefined,
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

pub const AmdExtTable = struct {
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
