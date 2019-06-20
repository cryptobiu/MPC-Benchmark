cmake_minimum_required(VERSION 2.8)
project(GMW)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O3 -std=c++11 -maes -mpclmul -fPIC -no-pie")


INCLUDE_DIRECTORIES($ENV{HOME} $ENV{HOME}/libscapi/lib/OTExtensionBristol
        $ENV{HOME}/libscapi/install/include)

link_directories(/usr/ssl/lib/ $ENV{HOME}/libscapi/install/lib)

set(SOURCE_FILES main.cpp Circuit.cpp GMWParty.cpp)
add_executable(GMW ${SOURCE_FILES})

TARGET_LINK_LIBRARIES(GMW $ENV{HOME}/libscapi/libscapi.a
        OTExtensionBristol libsimpleot.a
        boost_system boost_thread pthread crypto dl gmp ssl z)
