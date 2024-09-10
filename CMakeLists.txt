cmake_minimum_required(VERSION 3.10)

project(client VERSION 1.0)

add_executable(client client.cpp)
target_link_libraries(client ssl)
target_link_libraries(client crypto)