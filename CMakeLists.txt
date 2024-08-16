# https://github.com/Chainski/PandaLoader
cmake_minimum_required(VERSION 3.8)
project(PandaLoader)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(BUILD_SHARED_LIBS OFF)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -masm=intel -w -Os -static -mwindows -s")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--gc-sections")
set(SOURCE_FILES
    PandaLoader.cpp
)
include_directories(${CMAKE_SOURCE_DIR})
add_executable(PandaLoader ${SOURCE_FILES})
target_link_libraries(PandaLoader wininet)
