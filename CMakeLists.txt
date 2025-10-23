cmake_minimum_required(VERSION 3.20)
project(attendance LANGUAGES CXX)

# ---- C++ standard ----
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ---- Dependencies found via vcpkg toolchain ----
find_package(httplib CONFIG REQUIRED)                # target: httplib::httplib
find_package(unofficial-sqlite3 CONFIG REQUIRED)     # target: unofficial::sqlite3::sqlite3
find_package(nlohmann_json CONFIG REQUIRED)          # target: nlohmann_json::nlohmann_json
find_package(SDL2 CONFIG REQUIRED)                   # targets: SDL2::SDL2 SDL2::SDL2main
find_package(OpenSSL REQUIRED)                       # targets: OpenSSL::SSL OpenSSL::Crypto

# ---- Executable ----
add_executable(attendance main.cpp)

# ---- qrencode (vcpkg port: libqrencode) ----
# This port does not ship a CMake config on some setups; follow vcpkg's suggested pattern.
find_path(QRENCODE_INCLUDE_DIR NAMES qrencode.h)
find_library(QRENCODE_LIBRARY_RELEASE NAMES qrencode)
find_library(QRENCODE_LIBRARY_DEBUG   NAMES qrencoded qrencode)

if (NOT QRENCODE_INCLUDE_DIR OR (NOT QRENCODE_LIBRARY_RELEASE AND NOT QRENCODE_LIBRARY_DEBUG))
  message(FATAL_ERROR "qrencode not found. Make sure libqrencode:x64-windows is installed with vcpkg.")
endif()

set(QRENCODE_LIBRARIES "")
if (QRENCODE_LIBRARY_RELEASE)
  list(APPEND QRENCODE_LIBRARIES optimized ${QRENCODE_LIBRARY_RELEASE})
endif()
if (QRENCODE_LIBRARY_DEBUG)
  list(APPEND QRENCODE_LIBRARIES debug ${QRENCODE_LIBRARY_DEBUG})
endif()

target_include_directories(attendance PRIVATE ${QRENCODE_INCLUDE_DIR})

# ---- Link everything ----
target_link_libraries(attendance
  PRIVATE
    httplib::httplib
    unofficial::sqlite3::sqlite3
    nlohmann_json::nlohmann_json
    SDL2::SDL2
    OpenSSL::SSL
    OpenSSL::Crypto
    ${QRENCODE_LIBRARIES}
)

# Optional: nicer warnings on MSVC
if (MSVC)
  target_compile_options(attendance PRIVATE /W4 /permissive-)
endif()
