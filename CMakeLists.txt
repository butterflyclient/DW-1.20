cmake_minimum_required(VERSION 3.24)
project(iw8_demonware LANGUAGES CXX)
add_executable(iw8-dw-server
    src/server.cpp
    src/host_os.cpp
    src/crypto_provider.cpp
    src/network.cpp
    src/platform.cpp
    src/platform_account_store.cpp
    src/platform_resources.cpp
    src/crypto.cpp
    src/lobby.cpp
    src/bandwidth.cpp
    src/services.cpp
    src/startup_services.cpp
    src/rest_services.cpp
    src/regulation_services.cpp
    src/objectstore_services.cpp
    src/account_services.cpp
    src/leaderboard_services.cpp
    src/engagement_services.cpp
    src/abtesting_services.cpp
    src/qos_services.cpp
    src/qos_provider.cpp
    src/marketplace_services.cpp
    src/inventory_validation_services.cpp
    src/achievement_services.cpp
    src/battlepass_services.cpp
    src/achievement_store.cpp
    src/matchmaking_services.cpp
    src/matchmaking_store.cpp
    src/tournament_services.cpp
    src/tournament_map_policy.cpp
    src/playlist_catalog.cpp
    src/channel_services.cpp
    src/channel_store.cpp
    src/clan_services.cpp
    src/mail_services.cpp
    src/identity_services.cpp
    src/identity_rest_services.cpp
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
add_executable(iw8-session-lease-contract-test tools/test-session-lease.cpp
    src/platform.cpp src/platform_account_store.cpp src/platform_resources.cpp
    src/network.cpp src/crypto.cpp src/crypto_provider.cpp src/host_os.cpp)
target_compile_features(iw8-session-lease-contract-test PRIVATE cxx_std_20)
target_compile_definitions(iw8-session-lease-contract-test PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
if(WIN32)
  target_link_libraries(iw8-dw-server PRIVATE ws2_32 bcrypt)
  target_link_libraries(iw8-session-lease-contract-test PRIVATE ws2_32 bcrypt)
else()
  find_package(OpenSSL 3 REQUIRED)
  find_package(Threads REQUIRED)
  target_link_libraries(iw8-dw-server PRIVATE OpenSSL::Crypto Threads::Threads)
  target_link_libraries(iw8-session-lease-contract-test PRIVATE OpenSSL::Crypto Threads::Threads)
  target_compile_options(iw8-session-lease-contract-test PRIVATE -Wall -Wextra -Wpedantic)
  target_compile_options(iw8-dw-server PRIVATE -Wall -Wextra -Wpedantic)
endif()
add_executable(iw8-playlist-contract-test tools/test-playlist-contract.cpp
    src/playlist_catalog.cpp src/crypto.cpp src/crypto_provider.cpp src/host_os.cpp)
target_compile_features(iw8-playlist-contract-test PRIVATE cxx_std_20)
target_compile_definitions(iw8-playlist-contract-test PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
if(WIN32)
  target_link_libraries(iw8-playlist-contract-test PRIVATE bcrypt)
else()
  target_link_libraries(iw8-playlist-contract-test PRIVATE OpenSSL::Crypto Threads::Threads)
endif()
add_executable(iw8-bandwidth-contract-test tools/test-bandwidth-port-pool.cpp
    src/bandwidth.cpp src/network.cpp src/crypto.cpp src/host_os.cpp src/crypto_provider.cpp)
target_compile_features(iw8-bandwidth-contract-test PRIVATE cxx_std_20)
target_compile_definitions(iw8-bandwidth-contract-test PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
if(WIN32)
  target_link_libraries(iw8-bandwidth-contract-test PRIVATE ws2_32 bcrypt)
else()
  target_link_libraries(iw8-bandwidth-contract-test PRIVATE OpenSSL::Crypto Threads::Threads)
endif()
if(WIN32)
add_executable(replay-update-client tools/replay-update-client.cpp integration/replay/DW_LocalPlatformCrypto.cpp)
target_compile_features(replay-update-client PRIVATE cxx_std_20)
target_compile_definitions(replay-update-client PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(replay-update-client PRIVATE bcrypt winhttp)
set_property(TARGET replay-update-client PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
add_library(iw8-dw-platform-client SHARED integration/replay/DW_LocalPlatformCrypto.cpp
    integration/replay/DW_LocalIdentity.cpp tools/identity-test-adapter.cpp)
target_compile_features(iw8-dw-platform-client PRIVATE cxx_std_20)
set_target_properties(iw8-dw-platform-client PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
add_executable(iw8-dw-identity-check tools/identity-file-diagnostic.cpp
    integration/replay/DW_LocalIdentity.cpp tools/identity-test-adapter.cpp)
target_compile_features(iw8-dw-identity-check PRIVATE cxx_std_20)
target_link_libraries(iw8-dw-identity-check PRIVATE bcrypt crypt32)
endif()
if(MSVC)
  target_compile_options(iw8-dw-server PRIVATE /W4 /WX /EHsc)
  target_compile_options(iw8-session-lease-contract-test PRIVATE /W4 /WX /EHsc)
  target_compile_options(iw8-playlist-contract-test PRIVATE /W4 /WX /EHsc)
  target_compile_options(iw8-dw-platform-client PRIVATE /W4 /WX /EHsc)
  target_compile_options(iw8-dw-identity-check PRIVATE /W4 /WX /EHsc)
  set_property(TARGET iw8-dw-identity-check PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()
