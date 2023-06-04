cmake_minimum_required(VERSION 3.25)

set(CMAKE_ANDROID_NDK C:/Users/hzhan/AppData/Local/Android/Sdk/ndk/25.2.9519653)
set(CMAKE_TOOLCHAIN_FILE ${CMAKE_ANDROID_NDK}/build/cmake/android.toolchain.cmake)
set(CMAKE_SYSTEM_NAME Android)
set(CMAKE_SYSTEM_VERSION 24)
set(CMAKE_ANDROID_ARCH_ABI arm64-v8a)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(ANDROID_ABI arm64-v8a)
set(ANDROID_PLATFORM android-26)
set(ANDROID_NDK ${CMAKE_ANDROID_NDK})

project(SoDumper)

set(CMAKE_CXX_STANDARD 17)

set(FLAG "-static-libstdc++ -fexceptions")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${FLAG}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${FLAG}")

if (NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(FLAG "-flto -fvisibility=hidden -fvisibility-inlines-hidden -ffunction-sections -fdata-sections -O3 -DNDEBUG -fno-stack-protector -Wno-builtin-macro-redefined -U__FILE__ -D__FILE__='\"\"'" "")

    set(LINKER_FLAGS "-flto -O3 -Wl,-exclude-libs,ALL -Wl,--gc-sections -Wl,--strip-all")
    set(CMAKE_SHARED_LINKER_FLAGS " ${CMAKE_SHARED_LINKER_FLAGS} ${LINKER_FLAGS}")
    set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} ${LINKER_FLAGS}")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${LINKER_FLAGS}")
else ()
    set(FLAG "-O0 -g")
endif ()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${FLAG}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${FLAG}")

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY
        ${CMAKE_SOURCE_DIR}/outputs/${CMAKE_ANDROID_ARCH_ABI}/
        ) # 重定向输出产物(可执行文件)

include_directories(
        include)

add_executable(SoDumper
        main.cpp
        pmparser.cpp
        ELF64/fix.cpp)
