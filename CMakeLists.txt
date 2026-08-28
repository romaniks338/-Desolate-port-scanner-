cmake_minimum_required(VERSION 3.14)
project(PortScanner VERSION 2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(WIN32)
    link_libraries(ws2_32)
endif()

include_directories(include)

add_executable(portscanner
    src/main.cpp
    src/arg_parser.cpp
    src/dns_resolver.cpp
    src/port_range.cpp
    src/scan_engine.cpp
    src/scan_types.cpp
    src/result.cpp
)
