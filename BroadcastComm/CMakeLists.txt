cmake_minimum_required(VERSION 3.5)
project(BCast)

set(CMAKE_CXX_STANDARD 11)
set("${CMAKE_CXX_FLAGS} -g -O3")


INCLUDE_DIRECTORIES($ENV{HOME} $ENV{HOME}/libscapi/install/include/)

set(SOURCE_FILES main.cpp BCast.cpp)

link_directories(/usr/ssl/lib/ $ENV{HOME}/libscapi/install/lib)

add_executable(BCast ${SOURCE_FILES})

TARGET_LINK_LIBRARIES(BCast $ENV{HOME}/libscapi/libscapi.a gmp gmpxx libboost_system.a pthread dl)