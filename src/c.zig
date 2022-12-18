//! This module is used to import hsa.h and fix up/redefine some types from hsa_api_trace.h
//! that could not be parsed by translate-c, because they are actually c++.

pub const c = @cImport({
    @cInclude("hsa/hsa.h");
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

    hsa_init_fn: *const @TypeOf(c.hsa_init),
    hsa_shut_down_fn: *const @TypeOf(c.hsa_shut_down),
    hsa_system_get_info_fn: *const @TypeOf(c.hsa_system_get_info),
    hsa_system_extension_supported_fn: *const @TypeOf(c.hsa_system_extension_supported),
    hsa_system_get_extension_table_fn: *const @TypeOf(c.hsa_system_get_extension_table),
    hsa_iterate_agents_fn: *const @TypeOf(c.hsa_iterate_agents),
    hsa_agent_get_info_fn: *const @TypeOf(c.hsa_agent_get_info),
    hsa_queue_create_fn: *const @TypeOf(c.hsa_queue_create),
    hsa_soft_queue_create_fn: *const @TypeOf(c.hsa_soft_queue_create),
    hsa_queue_destroy_fn: *const @TypeOf(c.hsa_queue_destroy),
    hsa_queue_inactivate_fn: *const @TypeOf(c.hsa_queue_inactivate),
    hsa_queue_load_read_index_scacquire_fn: *const @TypeOf(c.hsa_queue_load_read_index_scacquire),
    hsa_queue_load_read_index_relaxed_fn: *const @TypeOf(c.hsa_queue_load_read_index_relaxed),
    hsa_queue_load_write_index_scacquire_fn: *const @TypeOf(c.hsa_queue_load_write_index_scacquire),
    hsa_queue_load_write_index_relaxed_fn: *const @TypeOf(c.hsa_queue_load_write_index_relaxed),
    hsa_queue_store_write_index_relaxed_fn: *const @TypeOf(c.hsa_queue_store_write_index_relaxed),
    hsa_queue_store_write_index_screlease_fn: *const @TypeOf(c.hsa_queue_store_write_index_screlease),
    hsa_queue_cas_write_index_scacq_screl_fn: *const @TypeOf(c.hsa_queue_cas_write_index_scacq_screl),
    hsa_queue_cas_write_index_scacquire_fn: *const @TypeOf(c.hsa_queue_cas_write_index_scacquire),
    hsa_queue_cas_write_index_relaxed_fn: *const @TypeOf(c.hsa_queue_cas_write_index_relaxed),
    hsa_queue_cas_write_index_screlease_fn: *const @TypeOf(c.hsa_queue_cas_write_index_screlease),
    hsa_queue_add_write_index_scacq_screl_fn: *const @TypeOf(c.hsa_queue_add_write_index_scacq_screl),
    hsa_queue_add_write_index_scacquire_fn: *const @TypeOf(c.hsa_queue_add_write_index_scacquire),
    hsa_queue_add_write_index_relaxed_fn: *const @TypeOf(c.hsa_queue_add_write_index_relaxed),
    hsa_queue_add_write_index_screlease_fn: *const @TypeOf(c.hsa_queue_add_write_index_screlease),
    hsa_queue_store_read_index_relaxed_fn: *const @TypeOf(c.hsa_queue_store_read_index_relaxed),
    hsa_queue_store_read_index_screlease_fn: *const @TypeOf(c.hsa_queue_store_read_index_screlease),
    hsa_agent_iterate_regions_fn: *const @TypeOf(c.hsa_agent_iterate_regions),
    hsa_region_get_info_fn: *const @TypeOf(c.hsa_region_get_info),
    hsa_agent_get_exception_policies_fn: *const @TypeOf(c.hsa_agent_get_exception_policies),
    hsa_agent_extension_supported_fn: *const @TypeOf(c.hsa_agent_extension_supported),
    hsa_memory_register_fn: *const @TypeOf(c.hsa_memory_register),
    hsa_memory_deregister_fn: *const @TypeOf(c.hsa_memory_deregister),
    hsa_memory_allocate_fn: *const @TypeOf(c.hsa_memory_allocate),
    hsa_memory_free_fn: *const @TypeOf(c.hsa_memory_free),
    hsa_memory_copy_fn: *const @TypeOf(c.hsa_memory_copy),
    hsa_memory_assign_agent_fn: *const @TypeOf(c.hsa_memory_assign_agent),
    hsa_signal_create_fn: *const @TypeOf(c.hsa_signal_create),
    hsa_signal_destroy_fn: *const @TypeOf(c.hsa_signal_destroy),
    hsa_signal_load_relaxed_fn: *const @TypeOf(c.hsa_signal_load_relaxed),
    hsa_signal_load_scacquire_fn: *const @TypeOf(c.hsa_signal_load_scacquire),
    hsa_signal_store_relaxed_fn: *const @TypeOf(c.hsa_signal_store_relaxed),
    hsa_signal_store_screlease_fn: *const @TypeOf(c.hsa_signal_store_screlease),
    hsa_signal_wait_relaxed_fn: *const @TypeOf(c.hsa_signal_wait_relaxed),
    hsa_signal_wait_scacquire_fn: *const @TypeOf(c.hsa_signal_wait_scacquire),
    hsa_signal_and_relaxed_fn: *const @TypeOf(c.hsa_signal_and_relaxed),
    hsa_signal_and_scacquire_fn: *const @TypeOf(c.hsa_signal_and_scacquire),
    hsa_signal_and_screlease_fn: *const @TypeOf(c.hsa_signal_and_screlease),
    hsa_signal_and_scacq_screl_fn: *const @TypeOf(c.hsa_signal_and_scacq_screl),
    hsa_signal_or_relaxed_fn: *const @TypeOf(c.hsa_signal_or_relaxed),
    hsa_signal_or_scacquire_fn: *const @TypeOf(c.hsa_signal_or_scacquire),
    hsa_signal_or_screlease_fn: *const @TypeOf(c.hsa_signal_or_screlease),
    hsa_signal_or_scacq_screl_fn: *const @TypeOf(c.hsa_signal_or_scacq_screl),
    hsa_signal_xor_relaxed_fn: *const @TypeOf(c.hsa_signal_xor_relaxed),
    hsa_signal_xor_scacquire_fn: *const @TypeOf(c.hsa_signal_xor_scacquire),
    hsa_signal_xor_screlease_fn: *const @TypeOf(c.hsa_signal_xor_screlease),
    hsa_signal_xor_scacq_screl_fn: *const @TypeOf(c.hsa_signal_xor_scacq_screl),
    hsa_signal_exchange_relaxed_fn: *const @TypeOf(c.hsa_signal_exchange_relaxed),
    hsa_signal_exchange_scacquire_fn: *const @TypeOf(c.hsa_signal_exchange_scacquire),
    hsa_signal_exchange_screlease_fn: *const @TypeOf(c.hsa_signal_exchange_screlease),
    hsa_signal_exchange_scacq_screl_fn: *const @TypeOf(c.hsa_signal_exchange_scacq_screl),
    hsa_signal_add_relaxed_fn: *const @TypeOf(c.hsa_signal_add_relaxed),
    hsa_signal_add_scacquire_fn: *const @TypeOf(c.hsa_signal_add_scacquire),
    hsa_signal_add_screlease_fn: *const @TypeOf(c.hsa_signal_add_screlease),
    hsa_signal_add_scacq_screl_fn: *const @TypeOf(c.hsa_signal_add_scacq_screl),
    hsa_signal_subtract_relaxed_fn: *const @TypeOf(c.hsa_signal_subtract_relaxed),
    hsa_signal_subtract_scacquire_fn: *const @TypeOf(c.hsa_signal_subtract_scacquire),
    hsa_signal_subtract_screlease_fn: *const @TypeOf(c.hsa_signal_subtract_screlease),
    hsa_signal_subtract_scacq_screl_fn: *const @TypeOf(c.hsa_signal_subtract_scacq_screl),
    hsa_signal_cas_relaxed_fn: *const @TypeOf(c.hsa_signal_cas_relaxed),
    hsa_signal_cas_scacquire_fn: *const @TypeOf(c.hsa_signal_cas_scacquire),
    hsa_signal_cas_screlease_fn: *const @TypeOf(c.hsa_signal_cas_screlease),
    hsa_signal_cas_scacq_screl_fn: *const @TypeOf(c.hsa_signal_cas_scacq_screl),

    //===--- Instruction Set Architecture -----------------------------------===//

    hsa_isa_from_name_fn: *const @TypeOf(c.hsa_isa_from_name),
    // Deprecated since v1.1.
    hsa_isa_get_info_fn: *const @TypeOf(c.hsa_isa_get_info),
    // Deprecated since v1.1.
    hsa_isa_compatible_fn: *const @TypeOf(c.hsa_isa_compatible),

    //===--- Code Objects (deprecated) --------------------------------------===//

    // Deprecated since v1.1.
    hsa_code_object_serialize_fn: *const @TypeOf(c.hsa_code_object_serialize),
    // Deprecated since v1.1.
    hsa_code_object_deserialize_fn: *const @TypeOf(c.hsa_code_object_deserialize),
    // Deprecated since v1.1.
    hsa_code_object_destroy_fn: *const @TypeOf(c.hsa_code_object_destroy),
    // Deprecated since v1.1.
    hsa_code_object_get_info_fn: *const @TypeOf(c.hsa_code_object_get_info),
    // Deprecated since v1.1.
    hsa_code_object_get_symbol_fn: *const @TypeOf(c.hsa_code_object_get_symbol),
    // Deprecated since v1.1.
    hsa_code_symbol_get_info_fn: *const @TypeOf(c.hsa_code_symbol_get_info),
    // Deprecated since v1.1.
    hsa_code_object_iterate_symbols_fn: *const @TypeOf(c.hsa_code_object_iterate_symbols),

    //===--- Executable -----------------------------------------------------===//

    // Deprecated since v1.1.
    hsa_executable_create_fn: *const @TypeOf(c.hsa_executable_create),
    hsa_executable_destroy_fn: *const @TypeOf(c.hsa_executable_destroy),
    // Deprecated since v1.1.
    hsa_executable_load_code_object_fn: *const @TypeOf(c.hsa_executable_load_code_object),
    hsa_executable_freeze_fn: *const @TypeOf(c.hsa_executable_freeze),
    hsa_executable_get_info_fn: *const @TypeOf(c.hsa_executable_get_info),
    hsa_executable_global_variable_define_fn: *const @TypeOf(c.hsa_executable_global_variable_define),
    hsa_executable_agent_global_variable_define_fn: *const @TypeOf(c.hsa_executable_agent_global_variable_define),
    hsa_executable_readonly_variable_define_fn: *const @TypeOf(c.hsa_executable_readonly_variable_define),
    hsa_executable_validate_fn: *const @TypeOf(c.hsa_executable_validate),
    // Deprecated since v1.1.
    hsa_executable_get_symbol_fn: *const @TypeOf(c.hsa_executable_get_symbol),
    hsa_executable_symbol_get_info_fn: *const @TypeOf(c.hsa_executable_symbol_get_info),
    // Deprecated since v1.1.
    hsa_executable_iterate_symbols_fn: *const @TypeOf(c.hsa_executable_iterate_symbols),

    //===--- Runtime Notifications ------------------------------------------===//

    hsa_status_string_fn: *const @TypeOf(c.hsa_status_string),

    // Start HSA v1.1 additions
    hsa_extension_get_name_fn: *const @TypeOf(c.hsa_extension_get_name),
    hsa_system_major_extension_supported_fn: *const @TypeOf(c.hsa_system_major_extension_supported),
    hsa_system_get_major_extension_table_fn: *const @TypeOf(c.hsa_system_get_major_extension_table),
    hsa_agent_major_extension_supported_fn: *const @TypeOf(c.hsa_agent_major_extension_supported),
    hsa_cache_get_info_fn: *const @TypeOf(c.hsa_cache_get_info),
    hsa_agent_iterate_caches_fn: *const @TypeOf(c.hsa_agent_iterate_caches),
    hsa_signal_silent_store_relaxed_fn: *const @TypeOf(c.hsa_signal_silent_store_relaxed),
    hsa_signal_silent_store_screlease_fn: *const @TypeOf(c.hsa_signal_silent_store_screlease),
    hsa_signal_group_create_fn: *const @TypeOf(c.hsa_signal_group_create),
    hsa_signal_group_destroy_fn: *const @TypeOf(c.hsa_signal_group_destroy),
    hsa_signal_group_wait_any_scacquire_fn: *const @TypeOf(c.hsa_signal_group_wait_any_scacquire),
    hsa_signal_group_wait_any_relaxed_fn: *const @TypeOf(c.hsa_signal_group_wait_any_relaxed),

    //===--- Instruction Set Architecture - HSA v1.1 additions --------------===//

    hsa_agent_iterate_isas_fn: *const @TypeOf(c.hsa_agent_iterate_isas),
    hsa_isa_get_info_alt_fn: *const @TypeOf(c.hsa_isa_get_info_alt),
    hsa_isa_get_exception_policies_fn: *const @TypeOf(c.hsa_isa_get_exception_policies),
    hsa_isa_get_round_method_fn: *const @TypeOf(c.hsa_isa_get_round_method),
    hsa_wavefront_get_info_fn: *const @TypeOf(c.hsa_wavefront_get_info),
    hsa_isa_iterate_wavefronts_fn: *const @TypeOf(c.hsa_isa_iterate_wavefronts),

    //===--- Code Objects (deprecated) - HSA v1.1 additions -----------------===//

    // Deprecated since v1.1.
    hsa_code_object_get_symbol_from_name_fn: *const @TypeOf(c.hsa_code_object_get_symbol_from_name),

    //===--- Executable - HSA v1.1 additions --------------------------------===//

    hsa_code_object_reader_create_from_file_fn: *const @TypeOf(c.hsa_code_object_reader_create_from_file),
    hsa_code_object_reader_create_from_memory_fn: *const @TypeOf(c.hsa_code_object_reader_create_from_memory),
    hsa_code_object_reader_destroy_fn: *const @TypeOf(c.hsa_code_object_reader_destroy),
    hsa_executable_create_alt_fn: *const @TypeOf(c.hsa_executable_create_alt),
    hsa_executable_load_program_code_object_fn: *const @TypeOf(c.hsa_executable_load_program_code_object),
    hsa_executable_load_agent_code_object_fn: *const @TypeOf(c.hsa_executable_load_agent_code_object),
    hsa_executable_validate_alt_fn: *const @TypeOf(c.hsa_executable_validate_alt),
    hsa_executable_get_symbol_by_name_fn: *const @TypeOf(c.hsa_executable_get_symbol_by_name),
    hsa_executable_iterate_agent_symbols_fn: *const @TypeOf(c.hsa_executable_iterate_agent_symbols),
    hsa_executable_iterate_program_symbols_fn: *const @TypeOf(c.hsa_executable_iterate_program_symbols),
};

// To add as needed
pub const AmdExtTable = anyopaque;
pub const FinalizerExtTable = anyopaque;
pub const ImageExtTable = anyopaque;

pub const ApiTable = extern struct {
    version: ApiTableVersion,
    core: *CoreApiTable,
    amd_ext: *AmdExtTable,
    finalizer_ext: *FinalizerExtTable,
    image_ext: *ImageExtTable,
};
