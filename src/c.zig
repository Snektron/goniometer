//! This module is used to import hsa.h and fix up/redefine some types from hsa_api_trace.h
//! that could not be parsed by translate-c, because they are actually c++.

pub const c = @cImport({
    @cInclude("hsa/hsa.h");
    @cInclude("hsa/hsa_ext_amd.h");
    @cInclude("hsa/hsa_ven_amd_aqlprofile.h");
});

pub usingnamespace c;

// TODO: Maybe this should not be put here, since there is no C equivalent.
pub const hsa_packet_t = struct {
    pub const alignment = 64;

    header: u16,
    body: [31]u16,

    pub fn packetType(self: *const hsa_packet_t) c.hsa_packet_type_t {
        return (self.header >> c.HSA_PACKET_HEADER_TYPE) & ((1 << c.HSA_PACKET_HEADER_WIDTH_TYPE) - 1);
    }
};

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
