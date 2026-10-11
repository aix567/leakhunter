cmake_minimum_required(VERSION 3.20)
project(leakhunter CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(leakhunter src/main.cpp src/http.cpp)

if (WIN32)
    target_compile_definitions(leakhunter PRIVATE
        _CRT_SECURE_NO_WARNINGS
        WIN32_LEAN_AND_MEAN
        NOMINMAX)
    target_link_libraries(leakhunter PRIVATE ws2_32 winhttp)
    if (MSVC)
        target_compile_options(leakhunter PRIVATE /utf-8 /W4)
    endif()
else()
    target_link_libraries(leakhunter PRIVATE pthread)
endif()