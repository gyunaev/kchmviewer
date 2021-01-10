
cmake_minimum_required(VERSION 3.0)

set(CPP_SOURCES
    chm_lib.c
    enum_chmLib.c
    enumdir_chmLib.c
    extract_chmLib.c
    lzx.c
    )

add_library(chm STATIC ${CPP_SOURCES})
target_include_directories(chm PUBLIC "./")
target_compile_options(chm PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/Wall>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra>
)
set_target_properties(chm PROPERTIES POSITION_INDEPENDENT_CODE ON)
