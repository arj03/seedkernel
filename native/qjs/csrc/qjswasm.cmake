# Included into quickjs-ng's own CMakeLists (build-qjs.sh passes this file as
# CMAKE_PROJECT_INCLUDE), so the engine's `qjs` library target is in scope. Builds shim.c
# against it as a WASI reactor and exports exactly the calls the Go bridge makes.

set(CMAKE_BUILD_TYPE "Release" CACHE STRING "" FORCE)
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON) # -flto for clang/wasm-ld

# Named against this file's own directory: the engine is a throwaway checkout under
# .build/, so a path relative to it would point outside the repo.
add_executable(qjswasm ${CMAKE_CURRENT_LIST_DIR}/shim.c)
set_target_properties(qjswasm PROPERTIES OUTPUT_NAME "qjswasm")
target_include_directories(qjswasm PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(qjswasm PRIVATE "-fvisibility=default")
target_link_libraries(qjswasm qjs)

# The shadow stack sits first in linear memory, so running off its end is an out-of-bounds
# trap rather than a write into the heap. The engine throws a catchable RangeError long
# before that: its limit is its default, JS_DEFAULT_STACK_SIZE (1 MiB), the stack is twice
# that, and the other half is headroom for the native frames between two of the engine's
# checks. Another 1.25 MiB of memory is committed up front for the heap.
#
# A reactor: the Go bridge runs `_initialize` once and then calls exports at will.
target_link_options(qjswasm PRIVATE
    -mexec-model=reactor
    "LINKER:--stack-first"
    "LINKER:-z,stack-size=2097152"
    "LINKER:--initial-memory=3407872"

    "LINKER:--export=malloc"
    "LINKER:--export=free"

    "LINKER:--export=QJS_New"
    "LINKER:--export=QJS_UpdateStackTop"
    "LINKER:--export=QJS_SetDeadline"
    "LINKER:--export=QJS_TakeInterrupted"
    "LINKER:--export=QJS_RunJobs"
    "LINKER:--export=QJS_TakeRejection"

    "LINKER:--export=QJS_FreeValue"
    "LINKER:--export=QJS_DupValue"
    "LINKER:--export=QJS_Null"
    "LINKER:--export=QJS_Undefined"
    "LINKER:--export=QJS_NewBool"
    "LINKER:--export=QJS_NewInt32"
    "LINKER:--export=QJS_NewInt64"
    "LINKER:--export=QJS_NewFloat64"
    "LINKER:--export=QJS_IsUndefined"
    "LINKER:--export=QJS_IsNull"
    "LINKER:--export=QJS_IsObject"
    "LINKER:--export=QJS_ToInt32"
    "LINKER:--export=QJS_ToInt64"

    "LINKER:--export=QJS_NewString"
    "LINKER:--export=QJS_ToCString"
    "LINKER:--export=JS_FreeCString"

    "LINKER:--export=QJS_NewArrayBuffer"
    "LINKER:--export=QJS_GetBytes"

    "LINKER:--export=QJS_NewFunction"
    "LINKER:--export=QJS_Call"
    "LINKER:--export=QJS_Eval"
    "LINKER:--export=QJS_ThrowError"

    "LINKER:--export=JS_GetGlobalObject"
    "LINKER:--export=JS_NewObject"
    "LINKER:--export=JS_GetPropertyStr"
    "LINKER:--export=JS_SetPropertyStr"
    "LINKER:--export=JS_HasException"
    "LINKER:--export=JS_GetException"
)
