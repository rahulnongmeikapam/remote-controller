cmake_minimum_required(VERSION 3.20)
project(RemoteControllerRefactored LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL 3 REQUIRED COMPONENTS Crypto)

add_library(remote_crypto STATIC
    common/crypto/Crypto.cpp
)
target_include_directories(remote_crypto PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/common/crypto
)
target_link_libraries(remote_crypto PUBLIC OpenSSL::Crypto)

if (WIN32)
    target_compile_definitions(remote_crypto PRIVATE WIN32_LEAN_AND_MEAN)
endif()

set(RC_COMMON_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/common/protocol)
set(RC_CRYPTO_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/common/crypto)
set(RC_STB_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/stb)

include(CTest)
if (BUILD_TESTING)
    add_executable(remote_crypto_tests tests/crypto_tests.cpp)
    target_link_libraries(remote_crypto_tests PRIVATE remote_crypto)
    add_test(NAME remote_crypto_tests COMMAND remote_crypto_tests)
endif()

if (WIN32)
    set(RC_WINDOWS_LIBS
        ws2_32 iphlpapi crypt32 advapi32 user32 gdi32 shell32
        ole32 oleaut32 uuid winmm d3d11 d3dcompiler
    )

    add_executable(rc_agent WIN32 apps/rc_agent.cpp)
    add_executable(rc_viewer WIN32 apps/rc_viewer.cpp)
    add_executable(rc_service apps/rc_service.cpp)

    foreach(target rc_agent rc_viewer rc_service)
        target_compile_definitions(${target} PRIVATE
            WIN32_LEAN_AND_MEAN
            NOMINMAX
            _WIN32_WINNT=0x0601
        )
        target_include_directories(${target} PRIVATE
            ${RC_COMMON_INCLUDE_DIR}
            ${RC_CRYPTO_INCLUDE_DIR}
            ${RC_STB_INCLUDE_DIR}
        )
        target_link_libraries(${target} PRIVATE remote_crypto ${RC_WINDOWS_LIBS})
    endforeach()
endif()
