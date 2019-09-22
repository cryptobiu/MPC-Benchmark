cmake_minimum_required(VERSION 2.8)
project(SemiHonestYao)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O3 -std=c++14 -march=armv8-a -Wno-ignored-attributes")

INCLUDE_DIRECTORIES($ENV{HOME} $ENV{HOME}/libscapi/install/include
        $ENV{HOME}/libscapi/install/include $ENV{HOME}/OTExtension/
        $ENV{HOME}/OTExtension/extern/ENCRYPTO_utils/src/)

set(SOURCE_FILES YaoParties.cpp App1.cpp)


link_directories($ENV{HOME}/OTExtension/)


add_executable(SemiHonestYao ${SOURCE_FILES})

TARGET_LINK_LIBRARIES(SemiHonestYao
        $ENV{HOME}/libscapi/libscapi.a gmp
        otextension.a
        boost_system boost_thread pthread crypto dl ssl z rt)
