cmake_minimum_required(VERSION 3.25)
project(custom_operator_model LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 20)
set(ZONETOOL "D:/mw124/mw120rproxy/iw8-zonetool/src" CACHE PATH "Reviewed Replay native writer source")
add_executable(custom-operator-model
    ${CMAKE_CURRENT_LIST_DIR}/custom-operator-model.cpp
    ${ZONETOOL}/zonetool/iw8/iw8_zone.cpp
    ${ZONETOOL}/zonetool/iw8/write_xmodel.cpp
    ${ZONETOOL}/zonetool/iw8/write_xsurface.cpp
    ${ZONETOOL}/zonetool/iw8/replay_render.cpp
    ${ZONETOOL}/zonetool/convert/conv_xsurface.cpp
    ${ZONETOOL}/zonetool/convert/conv_xmodel.cpp
    ${ZONETOOL}/zonetool/convert/xsurface.cpp
    ${ZONETOOL}/zonetool/dumpsrc/read_xmodel.cpp
    ${ZONETOOL}/zonetool/dumpsrc/read_xsurface.cpp
    ${ZONETOOL}/common/fs_util.cpp
    ${ZONETOOL}/common/ff_io.cpp)
target_include_directories(custom-operator-model PRIVATE ${ZONETOOL} ${ZONETOOL}/common ${ZONETOOL}/zonetool ${ZONETOOL}/thirdparty)
target_compile_definitions(custom-operator-model PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN _CRT_SECURE_NO_WARNINGS)
target_compile_options(custom-operator-model PRIVATE /Gy /EHsc)
target_link_options(custom-operator-model PRIVATE /OPT:REF /OPT:ICF)
target_link_libraries(custom-operator-model PRIVATE kernel32 d3dcompiler)
