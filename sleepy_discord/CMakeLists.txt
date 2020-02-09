cmake_minimum_required(VERSION 3.1)

project(sleepy-discord)

add_library(sleepy-discord STATIC
        ${CMAKE_CURRENT_LIST_DIR}/asignments_client.cpp
        ${CMAKE_CURRENT_LIST_DIR}/asio_udp.cpp
        ${CMAKE_CURRENT_LIST_DIR}/attachment.cpp
        ${CMAKE_CURRENT_LIST_DIR}/channel.cpp
        ${CMAKE_CURRENT_LIST_DIR}/client.cpp
        ${CMAKE_CURRENT_LIST_DIR}/cpr_session.cpp
        ${CMAKE_CURRENT_LIST_DIR}/default_functions.cpp
        ${CMAKE_CURRENT_LIST_DIR}/embed.cpp
        ${CMAKE_CURRENT_LIST_DIR}/endpoints.cpp
        ${CMAKE_CURRENT_LIST_DIR}/gateway.cpp
        ${CMAKE_CURRENT_LIST_DIR}/http.cpp
        ${CMAKE_CURRENT_LIST_DIR}/invite.cpp
        ${CMAKE_CURRENT_LIST_DIR}/json_wrapper.cpp
        ${CMAKE_CURRENT_LIST_DIR}/message.cpp
        ${CMAKE_CURRENT_LIST_DIR}/permissions.cpp
        ${CMAKE_CURRENT_LIST_DIR}/sd_error.cpp
        ${CMAKE_CURRENT_LIST_DIR}/server.cpp
        ${CMAKE_CURRENT_LIST_DIR}/user.cpp
        ${CMAKE_CURRENT_LIST_DIR}/uwebsockets_websocket.cpp
        ${CMAKE_CURRENT_LIST_DIR}/voice.cpp
        ${CMAKE_CURRENT_LIST_DIR}/voice_connection.cpp
        ${CMAKE_CURRENT_LIST_DIR}/webhook.cpp
        ${CMAKE_CURRENT_LIST_DIR}/websocketpp_websocket.cpp
        )

target_include_directories(sleepy-discord
        PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/../include/sleepy_discord
        PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/../include
        ${CMAKE_CURRENT_LIST_DIR}/../include/sleepy_discord/IncludeNonexistent)

set_target_properties(sleepy-discord PROPERTIES CXX_STANDARD 14)
set_target_properties(sleepy-discord PROPERTIES CXX_STANDARD_REQUIRED ON)
target_compile_features(sleepy-discord PUBLIC cxx_std_14)

target_link_libraries(sleepy-discord PUBLIC switch::opus switch::sodium)
target_compile_definitions(sleepy-discord PUBLIC
        SLEEPY_DISCORD_CMAKE SLEEPY_VOICE_ENABLED SLEEPY_ONE_THREAD
        SLEEPY_CUSTOM_SESSION SLEEPY_CUSTOM_UDP_CLIENT EXISTENT_OPUS
        EXISTENT_SODIUM SLEEPY_USE_HARD_CODED_GATEWAY)
