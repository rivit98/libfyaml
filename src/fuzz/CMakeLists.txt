set_source_files_properties(${CMAKE_CURRENT_SOURCE_DIR}/main.c
    PROPERTIES OBJECT_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/corpus.yaml
)

# ── fuzzing engine ────────────────────────────────────────────────────────────
# AFL++ is the only supported engine; libFuzzer is gone from this repo.
#
#   fuzz      the campaign binary. MUST be built with an afl-* compiler, which
#             is what -fsanitize=fuzzer on the link line means here: afl-cc
#             swaps it for its own libAFLDriver.a. It is EXCLUDE_FROM_ALL, so
#             only an explicit `--target fuzz` builds it - a plain-clang build
#             of everything would otherwise link the real libFuzzer runtime
#             behind that same flag and quietly bring the engine back.
#             fuzzer/build.sh is the supported way to build it.
#   fuzz2     the RR/RF reproducer, plain compiler, asan+ubsan - or msan with
#             -DFUZZ_REPRO_SANITIZER=memory
#   fuzz_cov  coverage, plain compiler, no sanitizers
#
# Both are built -DREPRODUCER: neither has a fuzzing engine to supply main(),
# and they share the one in fuzz_utils.h - argv takes input files or a
# vc<n>/tc<n> test case name.
#
# See fuzzer/ for the campaign scripts and src/fuzz/CLAUDE.md for triage.
# On the AFL path this file adds no instrumentation flags of its own - not the
# engine's, not the sanitizers'. Both come from the environment:
#
#   AFL_USE_ASAN=1 AFL_USE_UBSAN=1  cmake --build . --target fuzz
#   AFL_USE_MSAN=1                  cmake --build . --target fuzz
#   AFL_USE_LSAN=1                  cmake --build . --target fuzz
#   AFL_LLVM_CMPLOG=1               cmake --build . --target fuzz
#
# fuzzer/build.sh drives all of these.
set(FUZZ_AFL_DRIVER_LINK_OPTIONS -fsanitize=fuzzer)

# fuzz2's sanitizer. ASAN and MSAN cannot share a binary, so the MSAN
# reproducer is its own build tree (fuzzer/build.sh's repro-msan). MSAN also
# needs the library instrumented, which this file cannot do for a target it
# does not own: repro-msan passes -fsanitize=memory in CMAKE_C_FLAGS as well.
set(FUZZ_REPRO_SANITIZER "address" CACHE STRING
    "fuzz2 sanitizer: address (asan+ubsan) or memory (msan)")
set_property(CACHE FUZZ_REPRO_SANITIZER PROPERTY STRINGS address memory)
if(FUZZ_REPRO_SANITIZER STREQUAL "address")
    set(FUZZ_SANITIZER_OPTIONS -fsanitize=address,undefined -fno-sanitize-recover=all)
elseif(FUZZ_REPRO_SANITIZER STREQUAL "memory")
    set(FUZZ_SANITIZER_OPTIONS -fsanitize=memory -fsanitize-memory-track-origins=2)
else()
    message(FATAL_ERROR "FUZZ_REPRO_SANITIZER must be address or memory, not '${FUZZ_REPRO_SANITIZER}'")
endif()

set(FUZZ_BASE_OPTIONS -g -O2 -fno-omit-frame-pointer)

# ── shared pieces ─────────────────────────────────────────────────────────────
set(FUZZ_DEFS
    HAVE_CONFIG_H
    VERSION="${PROJECT_VERSION}"
    $<$<NOT:$<CONFIG:DEBUG>>:NDEBUG>
    ${COMMON_C_DEFINITIONS}
)

set(FUZZ_LIB_INCLUDES
    ${CMAKE_SOURCE_DIR}/src/lib
    ${CMAKE_SOURCE_DIR}/src/util
    ${CMAKE_SOURCE_DIR}/src/xxhash
    ${CMAKE_SOURCE_DIR}/src/thread
    ${CMAKE_SOURCE_DIR}/src/allocator
    ${CMAKE_SOURCE_DIR}/src/blake3
    ${CMAKE_SOURCE_DIR}/src/generic
    ${CMAKE_SOURCE_DIR}/src/reflection
    ${CMAKE_BINARY_DIR}
)

set(FUZZ_LIBSRCS "")
foreach(_src ${LIBSRCS})
    list(APPEND FUZZ_LIBSRCS ${CMAKE_SOURCE_DIR}/${_src})
endforeach()

# fuzz_add_library(<name> [SOURCES ...] [INCLUDES ...] [OPTIONS ...])
function(fuzz_add_library name)
    cmake_parse_arguments(A "" "" "SOURCES;INCLUDES;OPTIONS" ${ARGN})

    add_library(${name} STATIC ${FUZZ_LIBSRCS} ${A_SOURCES})

    set_target_properties(${name} PROPERTIES FOLDER "Libraries")

    target_include_directories(${name}
        PUBLIC
            ${CMAKE_SOURCE_DIR}/include
        PRIVATE
            ${A_INCLUDES}
            ${FUZZ_LIB_INCLUDES}
    )

    target_compile_definitions(${name} PRIVATE ${FUZZ_DEFS})
    target_compile_options(${name} PRIVATE ${A_OPTIONS} ${COMMON_C_FLAGS})

    target_link_libraries(${name} PUBLIC Threads::Threads)
    if(LIBM)
        target_link_libraries(${name} PUBLIC ${LIBM})
    endif()
    if(ATOMIC_LIBS)
        target_link_libraries(${name} PUBLIC ${ATOMIC_LIBS})
    endif()

    add_libclang_to_target(${name} INTERFACE)
endfunction()

# Allocation failure injection (fuzz_alloc_fail.h). Every malloc/calloc/realloc
# reference in a statically linked object - the harness and the library
# archive - goes through __wrap_*, which fails the one flags_t.alloc_fail_nth
# names. Shared objects are untouched, so a harness must link the library
# statically for this to reach it.
set(FUZZ_ALLOC_WRAP_LINK_OPTIONS
    -Wl,--wrap=malloc
    -Wl,--wrap=calloc
    -Wl,--wrap=realloc
)

# fuzz_add_harness(<name> LIBRARY <lib> [SOURCES ...] [INCLUDES ...] [OPTIONS ...] [LINK_OPTIONS ...])
function(fuzz_add_harness name)
    cmake_parse_arguments(A "" "LIBRARY" "SOURCES;INCLUDES;OPTIONS;LINK_OPTIONS;LINK_LIBRARIES" ${ARGN})

    add_executable(${name} ${CMAKE_CURRENT_SOURCE_DIR}/main.c ${A_SOURCES})

    set_target_properties(${name} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
    )

    target_compile_options(${name} PRIVATE ${A_OPTIONS} ${COMMON_C_FLAGS})
    target_compile_definitions(${name} PRIVATE ${FUZZ_DEFS})

    target_include_directories(${name} PRIVATE
        ${A_INCLUDES}
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_BINARY_DIR}
    )

    target_link_libraries(${name} PRIVATE ${A_LIBRARY} ${A_LINK_LIBRARIES})
    target_link_options(${name} PRIVATE ${A_LINK_OPTIONS} ${FUZZ_ALLOC_WRAP_LINK_OPTIONS} -rdynamic)

    add_libclang_to_target(${name} PRIVATE)
endfunction()


# ── private BLAKE3 backends ───────────────────────────────────────────────────
set(BLAKE3_BACKEND_SPECS "portable|1||")
if(TARGET_HAS_SSE2)
    list(APPEND BLAKE3_BACKEND_SPECS "sse2|4|-msse2|blake3_sse2_x86-64_unix.S")
endif()
if(TARGET_HAS_SSE41)
    list(APPEND BLAKE3_BACKEND_SPECS "sse41|4|-msse4.1|blake3_sse41_x86-64_unix.S")
endif()
if(TARGET_HAS_AVX2)
    list(APPEND BLAKE3_BACKEND_SPECS "avx2|8|-mavx2|blake3_avx2_x86-64_unix.S")
endif()
if(TARGET_HAS_AVX512)
    list(APPEND BLAKE3_BACKEND_SPECS "avx512|16|-mavx512f -mavx512vl|blake3_avx512_x86-64_unix.S")
endif()
if(TARGET_HAS_NEON)
    if(TARGET_CPU_ARM)
        list(APPEND BLAKE3_BACKEND_SPECS "neon|4|-mfpu=neon|")
    else()
        list(APPEND BLAKE3_BACKEND_SPECS "neon|4||")
    endif()
endif()

# blake3_objects(<out-var> <name-suffix> [OPTIONS <...>])
function(blake3_objects out_var name_suffix)
    cmake_parse_arguments(B "" "" "OPTIONS" ${ARGN})
    set(_objs "")

    foreach(_spec ${BLAKE3_BACKEND_SPECS})
        string(REPLACE "|" ";" _fields "${_spec}")
        list(GET _fields 0 _name)
        list(GET _fields 1 _degree)
        list(GET _fields 2 _isa)
        list(GET _fields 3 _asm)

        set(_target b3${_name}${name_suffix})
        set(_srcs
            ${CMAKE_SOURCE_DIR}/src/blake3/blake3_${_name}.c
            ${CMAKE_SOURCE_DIR}/src/blake3/blake3.c
        )
        if(_asm)
            list(APPEND _srcs ${CMAKE_SOURCE_DIR}/src/blake3/${_asm})
        endif()
        separate_arguments(_isa)

        add_library(${_target} OBJECT ${_srcs})

        target_include_directories(${_target} PRIVATE
            ${CMAKE_SOURCE_DIR}/include
            ${CMAKE_SOURCE_DIR}/src/util
            ${CMAKE_SOURCE_DIR}/src/thread
            ${CMAKE_SOURCE_DIR}/src/blake3
            ${CMAKE_BINARY_DIR}
        )
        target_compile_definitions(${_target} PRIVATE
            ${COMMON_C_DEFINITIONS}
            HASHER_SUFFIX=${_name}
            SIMD_DEGREE=${_degree}
        )
        target_compile_options(${_target} PRIVATE
            ${COMMON_C_FLAGS}
            ${_isa}
            ${B_OPTIONS}
            ${LIB_OPTS}
        )
        set_property(TARGET ${_target} PROPERTY
            POSITION_INDEPENDENT_CODE "${CMAKE_POSITION_INDEPENDENT_CODE}"
        )

        list(APPEND _objs $<TARGET_OBJECTS:${_target}>)
    endforeach()

    set(${out_var} ${_objs} PARENT_SCOPE)
endfunction()


# ── fuzz ──────────────────────────────────────────────────────────────────────
# The campaign binary. Instrumentation and sanitizers come from the AFL_USE_*
# environment variables (see above); this file adds none of its own.
set(AFL_OPTIONS ${FUZZ_BASE_OPTIONS})

blake3_objects(AFL_BLAKE3 "_afl" OPTIONS ${AFL_OPTIONS})

fuzz_add_library(fyaml_afl
    SOURCES ${AFL_BLAKE3}
    OPTIONS ${AFL_OPTIONS}
)

fuzz_add_harness(fuzz
    LIBRARY      fyaml_afl
    OPTIONS      ${AFL_OPTIONS}
    LINK_OPTIONS ${FUZZ_AFL_DRIVER_LINK_OPTIONS}
)

# Built on demand only - see the note at the top of this file.
set_target_properties(fuzz fyaml_afl PROPERTIES EXCLUDE_FROM_ALL TRUE)
foreach(_spec ${BLAKE3_BACKEND_SPECS})
    string(REPLACE "|" ";" _fields "${_spec}")
    list(GET _fields 0 _name)
    set_target_properties(b3${_name}_afl PROPERTIES EXCLUDE_FROM_ALL TRUE)
endforeach()

# ── fuzz2 ─────────────────────────────────────────────────────────────────────
# fyaml_static, not the shared fyaml: --wrap cannot reach into a shared object,
# and an allocation failure the fuzzer found has to replay here. It gets the
# same -O2 and ASAN_C_FLAGS as the shared library under -DENABLE_ASAN=ON.
fuzz_add_harness(fuzz2
    LIBRARY      fyaml_static
    OPTIONS      ${FUZZ_BASE_OPTIONS} ${FUZZ_SANITIZER_OPTIONS} -O0 -DREPRODUCER
    LINK_OPTIONS ${FUZZ_SANITIZER_OPTIONS}
)

# ── fuzz_cov ──────────────────────────────────────────────────────────────────
# Coverage build. No fuzzing engine and no sanitizers: -DREPRODUCER brings in
# the shared entry point, so this runs the corpus files given on the command
# line and `make coverage` works whether or not an AFL toolchain is installed.
set(COV_C_FLAGS -fprofile-instr-generate -fcoverage-mapping)
set(COV_LIB_OPTIONS ${FUZZ_BASE_OPTIONS} ${COV_C_FLAGS})

blake3_objects(COV_BLAKE3_OBJECTS "_cov" OPTIONS ${COV_LIB_OPTIONS})

fuzz_add_library(fyaml_cov
    SOURCES ${COV_BLAKE3_OBJECTS}
    OPTIONS ${COV_LIB_OPTIONS}
)

fuzz_add_harness(fuzz_cov
    LIBRARY      fyaml_cov
    OPTIONS      ${COV_LIB_OPTIONS} -DREPRODUCER
    LINK_OPTIONS ${COV_C_FLAGS}
)
