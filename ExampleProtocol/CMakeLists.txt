cmake_minimum_required(VERSION 3.5)
project(ExampleProtocol)

set(CMAKE_CXX_STANDARD 11)
set("${CMAKE_CXX_FLAGS} -g -O3")


INCLUDE_DIRECTORIES($ENV{HOME} $ENV{HOME}/libscapi/install/include/)

set(SOURCE_FILES main.cpp ExampleUdp.cpp ExampleProtocol.cpp)

link_directories(/usr/ssl/lib/ $ENV{HOME}/libscapi/install/lib)

add_executable(ExampleProtocol ${SOURCE_FILES})

TARGET_LINK_LIBRARIES(ExampleProtocol $ENV{HOME}/libscapi/libscapi.a
        gmp log4cpp boost_system pthread dl $ENV{HOME}/libscapi/install/lib/ikcp.a)