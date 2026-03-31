# Fuzz targets
# Variables consumed from the parent scope:
#   COMMON_C_FLAGS, COMMON_C_DEFINITIONS, LIBSRCS, BLAKE3_TARGETS,
#   LIBCLANG_LIBS, LIBCLANG_LINK_DIRS, LIBM, PROJECT_VERSION
# Targets consumed from the parent scope:
#   fyaml, Threads::Threads
# Macros consumed from the parent scope:
#   add_libclang_to_target

# ── fuzz ──────────────────────────────────────────────────────────────────────
add_executable(fuzz
    ${CMAKE_CURRENT_SOURCE_DIR}/main.c
)

set_target_properties(fuzz PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)

target_compile_options(fuzz PRIVATE
    -g
    -O2
    -fsanitize=fuzzer,address,signed-integer-overflow,undefined
    -fprofile-instr-generate
    -fcoverage-mapping
    -fno-omit-frame-pointer
    ${COMMON_C_FLAGS}
)

target_compile_definitions(fuzz PRIVATE
    HAVE_CONFIG_H
    VERSION="${PROJECT_VERSION}"
    $<$<NOT:$<CONFIG:DEBUG>>:NDEBUG>
    ${COMMON_C_DEFINITIONS}
)

target_include_directories(fuzz PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
)

# IMPORTANT: instrument the actual library compilation
target_compile_options(fyaml_static PRIVATE
    -g
    -O2
    -fprofile-instr-generate
    -fcoverage-mapping
    -fno-omit-frame-pointer
)

target_link_libraries(fuzz PRIVATE
    fyaml_static
)

target_link_options(fuzz PRIVATE
    -fsanitize=fuzzer,address,signed-integer-overflow,undefined
    -fprofile-instr-generate
    -rdynamic
)

add_libclang_to_target(fuzz PRIVATE)



add_executable(fuzz2
    ${CMAKE_CURRENT_SOURCE_DIR}/main.c
)

set_target_properties(fuzz2 PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)

target_compile_options(fuzz2
    PRIVATE
        -g
        -O0
        -fsanitize=address,signed-integer-overflow,undefined
        # -fsanitize=memory,signed-integer-overflow,undefined
        # -fsanitize-memory-track-origins
        -fno-omit-frame-pointer
        -DREPRODUCER
        ${COMMON_C_FLAGS}
)

target_include_directories(fuzz2
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_BINARY_DIR}
)

target_compile_definitions(fuzz2
    PRIVATE
        HAVE_CONFIG_H
        VERSION="${PROJECT_VERSION}"
        $<$<NOT:$<CONFIG:DEBUG>>:NDEBUG>
        ${COMMON_C_DEFINITIONS}
)

target_link_libraries(fuzz2
    PRIVATE
        fyaml
)

target_link_options(fuzz2
    PRIVATE
        -fsanitize=address,signed-integer-overflow,undefined
        # -fsanitize=memory,signed-integer-overflow,undefined
        # -fsanitize-memory-track-origins
        -rdynamic
)

add_libclang_to_target(fuzz2 PRIVATE)

