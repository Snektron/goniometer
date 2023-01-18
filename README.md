# Goniometer

Goniometer is a work-in-progress profiling tool for ROCm, specifically targetting Linux.

> A goniometer is a tool sometimes used to measure angles of features in roc(k) samples.

## Building

### Dependencies

Goniometer is written in [zig](https://ziglang.org/), and requires a recent version to build. Additionally, the HSA headers are required. The build file automatically searches for these in the standard include paths as well as `/opt/rocm/include`, which is where the headers are installed by the default ROCm distribution. Alternatively, they can be obtained from [ROCR-Runtime](https://github.com/RadeonOpenCompute/ROCR-Runtime/commits/master/src/inc/) by adding `--search-prefix path/to/ROCR-Runtime/src/inc`.

### Compiling

The project can be compiled by running `zig build` in the root directory. The produced binaries are placed in `zig-out/bin` and `zig-out/lib` by default, though this path can be overridden by passing `--prefix <path>` to the build command.

## Usage

Currently, goniometer can be used to gather [RadeonGPUProfiler](https://gpuopen.com/rgp/) compatible traces for gfx1030 based GPUs. These traces only contain the neccesary elements to be able to view [instruction timing](https://radeon-gpuprofiler.readthedocs.io/en/latest/#instruction-timing), which shows for each instruction of a kernel the number of cycles that it took to execute it.

Goniometer currently exposes itself as an HSA tool. HSA tools can be loaded by the AMD HSA runtime (ROCR-Runtime) by setting the `HSA_TOOLS_LIB` environment variable to the path of `libgoniometer.so` when executing a ROCm HIP program. All all kernels are traced, and the corresponding trace is saved as `dump-<n>.rgp`, where `<n>` is an arbitrary number representing the GPU that the trace was gathered from.

## Internals

On Linux, the ROCm runtime uses the "architected queuing language" (AQL) to schedule work on the GPU. This is disctinctly different from PM4, the traditional command stream accepted by AMD GPUs. There is no (known) way to configure performance counters and SQTT tracing via AQL, but fortunately way there is an escape hatch, a [HSA extension packet](https://github.com/RadeonOpenCompute/ROCR-Runtime/blob/a0d5e18e7752563daf4da970eae5ac8b6056a4c0/src/inc/hsa_ven_amd_aqlprofile.h#L202) which enables PM4 execution via an AQL queue. This is also used by rocprof itself to perform performance tracking, and it means that we can use the code used by Mesa, AMDPAL, and rocprof, to configure the GPU to gather the right information.

## Resources on profiling AMD GPUs

Some relevant information for gathering tracing information can be found in the following resources:

- The [AMDPAL](https://github.com/GPUOpen-Drivers/pal) driver offers the most complete public implementation for profiling AMD GPUs. In particular, look in `gpaSession.cpp` and the calls it makes. This project also has header definitions for the .rgp file format.
- [xgl](https://github.com/GPUOpen-Drivers/xgl/) interacts with the GpaSession from an SQTT layer. `sqtt_layer.cpp` is interesting in particular, as well as `sqtt_rgp_annotations.h`, which contains some information about the SQTT event format.
- [Mesa](https://gitlab.freedesktop.org/mesa/mesa) has some tracing functionality. `radv_sqtt.c` and `ac_rgp.c` are useful references.
- [HSA headers](https://github.com/RadeonOpenCompute/ROCR-Runtime/commits/master/src/inc/) show how to interact with the HSA runtime.
- [rocprof](https://github.com/ROCm-Developer-Tools/rocprofiler) is ROCm's official profiling tool. Unfortunately it does not support gathering SQTT traces (or any GPU above gfx9 in fact).
