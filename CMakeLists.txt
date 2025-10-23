cmake_minimum_required(VERSION 3.20)
project(attendance LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ---- Dependencies from vcpkg toolchain ----
find_package(httplib CONFIG REQUIRED)                # httplib::httplib
find_package(unofficial-sqlite3 CONFIG REQUIRED)     # unofficial::sqlite3::sqlite3
find_package(nlohmann_json CONFIG REQUIRED)          # nlohmann_json::nlohmann_json
find_package(SDL2 CONFIG REQUIRED)                   # SDL2::SDL2
find_package(OpenSSL REQUIRED)                       # OpenSSL::SSL OpenSSL::Crypto
find_package(imgui CONFIG REQUIRED)                  # imgui::imgui
find_package(OpenGL REQUIRED)                        # OpenGL::GL

# ---- Executable ----
add_executable(attendance main.cpp)

# ---- qrencode (vcpkg port: libqrencode does not ship a CMake config) ----
find_path(QRENCODE_INCLUDE_DIR NAMES qrencode.h)
find_library(QRENCODE_LIBRARY_RELEASE NAMES qrencode)
find_library(QRENCODE_LIBRARY_DEBUG   NAMES qrencoded qrencode)
if (NOT QRENCODE_INCLUDE_DIR OR (NOT QRENCODE_LIBRARY_RELEASE AND NOT QRENCODE_LIBRARY_DEBUG))
  message(FATAL_ERROR "qrencode not found. Install libqrencode:x64-windows via vcpkg.")
endif()
set(QRENCODE_LIBRARIES "")
if (QRENCODE_LIBRARY_RELEASE)
  list(APPEND QRENCODE_LIBRARIES optimized ${QRENCODE_LIBRARY_RELEASE})
endif()
if (QRENCODE_LIBRARY_DEBUG)
  list(APPEND QRENCODE_LIBRARIES debug ${QRENCODE_LIBRARY_DEBUG})
endif()
target_include_directories(attendance PRIVATE ${QRENCODE_INCLUDE_DIR})

# ---- Dear ImGui backends (SDL2 + OpenGL3) ----
# You passed IMGUI_BACKENDS_DIR in CMakePresets.json.
if (NOT DEFINED IMGUI_BACKENDS_DIR OR NOT EXISTS "${IMGUI_BACKENDS_DIR}")
  message(FATAL_ERROR
    "ImGui backends not found. Set -DIMGUI_BACKENDS_DIR to the folder that contains "
    "imgui_impl_sdl2.cpp and imgui_impl_opengl3.cpp")
endif()

# Compile backend sources
target_sources(attendance PRIVATE
  ${IMGUI_BACKENDS_DIR}/imgui_impl_sdl2.cpp
  ${IMGUI_BACKENDS_DIR}/imgui_impl_opengl3.cpp
)

# Make sure main.cpp can #include the backend headers from that folder
target_include_directories(attendance PRIVATE
  ${IMGUI_BACKENDS_DIR}
)

# ---- Link everything (NOTE: do NOT link SDL2main; we use SDL_MAIN_HANDLED) ----
target_link_libraries(attendance
  PRIVATE
    httplib::httplib
    unofficial::sqlite3::sqlite3
    nlohmann_json::nlohmann_json
    SDL2::SDL2
    imgui::imgui
    OpenSSL::SSL
    OpenSSL::Crypto
    OpenGL::GL
    ${QRENCODE_LIBRARIES}
)

if (MSVC)
  target_compile_options(attendance PRIVATE /W4 /permissive-)
endif()
