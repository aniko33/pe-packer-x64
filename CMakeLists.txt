cmake_minimum_required(VERSION 3.0)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_C_COMPILER    x86_64-w64-mingw32-gcc)
set(CMAKE_CXX_COMPILER  x86_64-w64-mingw32-g++)

project("PE-Packer-x64")
add_executable("main" "main.c")
