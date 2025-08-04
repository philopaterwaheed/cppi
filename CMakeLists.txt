cmake_minimum_required(VERSION 3.15)

project(cppi 
    VERSION 1.0.0 
    DESCRIPTION "Modern C++ HTTP Server and Client Library"
    LANGUAGES CXX
)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Compiler-specific options
if(MSVC)
    add_compile_options(/W4)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# Find required packages
find_package(Threads REQUIRED)

# On Windows, link with Winsock
if(WIN32)
    set(PLATFORM_LIBS ws2_32)
else()
    set(PLATFORM_LIBS)
endif()

# Header-only library interface
add_library(cppi INTERFACE)
target_include_directories(cppi INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include>
)
target_link_libraries(cppi INTERFACE 
    Threads::Threads 
    ${PLATFORM_LIBS}
)
target_compile_features(cppi INTERFACE cxx_std_17)

# Examples (optional)
option(CPPI_BUILD_EXAMPLES "Build CPPI examples" ON)

if(CPPI_BUILD_EXAMPLES)
    add_executable(simple_test simple_test.cpp)
    target_link_libraries(simple_test PRIVATE cppi)
    
    add_executable(example_server example_server.cpp)
    target_link_libraries(example_server PRIVATE cppi)
    
    add_executable(example_client example_client.cpp)
    target_link_libraries(example_client PRIVATE cppi)
    
    add_executable(example_streaming example_streaming.cpp)
    target_link_libraries(example_streaming PRIVATE cppi)
    
    add_executable(integration_test integration_test.cpp)
    target_link_libraries(integration_test PRIVATE cppi)
endif()

# Installation
install(TARGETS cppi
    EXPORT cppiTargets
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
    INCLUDES DESTINATION include
)

install(FILES 
    cppi.hpp
    types.hpp
    errors.hpp
    helpers.hpp
    utils.hpp
    DESTINATION include/cppi
)

install(DIRECTORY external/json/single_include/nlohmann
    DESTINATION include
)

# Export targets
install(EXPORT cppiTargets
    FILE cppiTargets.cmake
    NAMESPACE cppi::
    DESTINATION lib/cmake/cppi
)

# Create config files
include(CMakePackageConfigHelpers)

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/cppiConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/cppiConfig.cmake"
    INSTALL_DESTINATION lib/cmake/cppi
)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/cppiConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/cppiConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/cppiConfigVersion.cmake"
    DESTINATION lib/cmake/cppi
)
