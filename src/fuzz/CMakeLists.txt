set_source_files_properties(${CMAKE_CURRENT_SOURCE_DIR}/main.c
    PROPERTIES OBJECT_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/corpus.yaml
)

# ── fuzzing engine ────────────────────────────────────────────────────────────
get_filename_component(_fuzz_cc_name "${CMAKE_C_COMPILER}" NAME)
if(_fuzz_cc_name MATCHES "^afl-")
    set(FUZZ_ENGINE_AFL TRUE)
else()
    set(FUZZ_ENGINE_AFL FALSE)
endif()

# On the AFL path this file adds no instrumentation flags of its own - not the
# engine's, not the sanitizers'. Both come from the environment:
#
#   AFL_USE_ASAN=1 AFL_USE_UBSAN=1  make build CC=afl-clang-fast
#   AFL_USE_MSAN=1 AFL_USE_UBSAN=1  make build CC=afl-clang-fast
if(FUZZ_ENGINE_AFL)
    set(FUZZ_ENGINE_COMPILE_OPTIONS "")
    set(FUZZ_SANITIZER_OPTIONS "")
    message(STATUS "fuzz: AFL build - sanitizers come from AFL_USE_* in the environment")
else()
    set(FUZZ_ENGINE_COMPILE_OPTIONS -fsanitize=fuzzer-no-link)
    set(FUZZ_SANITIZER_OPTIONS -fsanitize=address,undefined -fno-sanitize-recover=all)
endif()
set(FUZZ_ENGINE_LINK_OPTIONS -fsanitize=fuzzer)

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

# fuzz_add_harness(<name> LIBRARY <lib> [INCLUDES ...] [OPTIONS ...] [LINK_OPTIONS ...])
function(fuzz_add_harness name)
    cmake_parse_arguments(A "" "LIBRARY" "INCLUDES;OPTIONS;LINK_OPTIONS;LINK_LIBRARIES" ${ARGN})

    add_executable(${name} ${CMAKE_CURRENT_SOURCE_DIR}/main.c)

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
    target_link_options(${name} PRIVATE ${A_LINK_OPTIONS} -rdynamic)

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
set(ASAN_OPTIONS ${FUZZ_BASE_OPTIONS} ${FUZZ_ENGINE_COMPILE_OPTIONS} ${FUZZ_SANITIZER_OPTIONS})

blake3_objects(ASAN_BLAKE3 "_asan" OPTIONS ${ASAN_OPTIONS})

fuzz_add_library(fyaml_asan
    SOURCES ${ASAN_BLAKE3}
    OPTIONS ${ASAN_OPTIONS}
)

fuzz_add_harness(fuzz
    LIBRARY      fyaml_asan
    OPTIONS      ${ASAN_OPTIONS}
    LINK_OPTIONS ${FUZZ_ENGINE_LINK_OPTIONS} ${FUZZ_SANITIZER_OPTIONS}
)

# ── fuzz2 ─────────────────────────────────────────────────────────────────────
fuzz_add_harness(fuzz2
    LIBRARY      fyaml
    OPTIONS      ${FUZZ_BASE_OPTIONS} ${FUZZ_SANITIZER_OPTIONS} -O0 -DREPRODUCER
    LINK_OPTIONS ${FUZZ_SANITIZER_OPTIONS}
)

# ── fuzz_cov ──────────────────────────────────────────────────────────────────
set(COV_C_FLAGS -fprofile-instr-generate -fcoverage-mapping)
set(COV_LIB_OPTIONS ${FUZZ_BASE_OPTIONS} ${COV_C_FLAGS})
set(COV_OPTIONS ${COV_LIB_OPTIONS} ${FUZZ_ENGINE_COMPILE_OPTIONS})

blake3_objects(COV_BLAKE3_OBJECTS "_cov" OPTIONS ${COV_LIB_OPTIONS})

fuzz_add_library(fyaml_cov
    SOURCES ${COV_BLAKE3_OBJECTS}
    OPTIONS ${COV_LIB_OPTIONS}
)

fuzz_add_harness(fuzz_cov
    LIBRARY      fyaml_cov
    OPTIONS      ${COV_OPTIONS}
    LINK_OPTIONS ${FUZZ_ENGINE_LINK_OPTIONS} ${COV_C_FLAGS}
)
