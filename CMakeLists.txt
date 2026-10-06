cmake_minimum_required(VERSION 3.24)
project(iw8_demonware LANGUAGES CXX)
if(NOT WIN32)
  message(FATAL_ERROR "This initial server targets Windows")
endif()
add_executable(iw8-dw-server
    src/server.cpp
    src/network.cpp
    src/platform.cpp
    src/platform_resources.cpp
    src/crypto.cpp
    src/lobby.cpp
    src/bandwidth.cpp
    src/services.cpp
    src/startup_services.cpp
    src/rest_services.cpp
    src/objectstore_services.cpp
    src/account_services.cpp
    src/leaderboard_services.cpp
    src/engagement_services.cpp
    src/qos_services.cpp
    src/qos_provider.cpp
    src/marketplace_services.cpp
    src/inventory_validation_services.cpp
    src/achievement_services.cpp
    src/matchmaking_services.cpp
    src/matchmaking_store.cpp
    src/tournament_services.cpp
    src/playlist_catalog.cpp
    src/channel_services.cpp
    src/clan_services.cpp
    src/mail_services.cpp
    src/identity_services.cpp
    src/social_services.cpp
    src/scheduled_services.cpp
    src/counter_services.cpp
    src/team_services.cpp
    src/content_services.cpp
    src/anticheat_services.cpp
    src/relay_services.cpp
    src/relay_provider.cpp
)
target_compile_features(iw8-dw-server PRIVATE cxx_std_20)
target_compile_definitions(iw8-dw-server PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0601)
target_link_libraries(iw8-dw-server PRIVATE ws2_32 bcrypt)
add_library(iw8-dw-platform-client SHARED integration/replay/DW_LocalPlatformCrypto.cpp
    integration/replay/DW_LocalIdentity.cpp)
target_compile_features(iw8-dw-platform-client PRIVATE cxx_std_20)
set_target_properties(iw8-dw-platform-client PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
add_executable(iw8-dw-identity-check tools/identity-file-diagnostic.cpp
    integration/replay/DW_LocalIdentity.cpp)
target_compile_features(iw8-dw-identity-check PRIVATE cxx_std_20)
target_link_libraries(iw8-dw-identity-check PRIVATE bcrypt crypt32)
if(MSVC)
  target_compile_options(iw8-dw-server PRIVATE /W4 /WX /EHsc)
  target_compile_options(iw8-dw-platform-client PRIVATE /W4 /WX /EHsc)
  target_compile_options(iw8-dw-identity-check PRIVATE /W4 /WX /EHsc)
  set_property(TARGET iw8-dw-identity-check PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()
