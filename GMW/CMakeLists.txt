cmake_minimum_required(VERSION 2.8)
project(GMW)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -std=c++11 -maes -mpclmul -fPIC")


INCLUDE_DIRECTORIES($ENV{HOME} ${BOOST_INCLUDEDIR} $ENV{HOME}
        $ENV{HOME}/libscapi/lib/OTExtensionBristol $ENV{HOME}/libscapi/lib/
        $ENV{HOME}/libscapi/install/include)

link_directories(/usr/ssl/lib/ $ENV{HOME}/libscapi/install/lib ${BOOST_LIBRARYDIR})

set(SOURCE_FILES main.cpp GMWParty.h Circuit.cpp Circuit.h MPCCommunication.cpp MPCCommunication.h GMWParty.cpp)
add_executable(GMW ${SOURCE_FILES})

TARGET_LINK_LIBRARIES(GMW $ENV{HOME}/libscapi/libscapi.a gmp
        OTExtensionBristol
        $ENV{HOME}/libscapi/install/lib/libsimpleot.a
        $ENV{HOME}/libscapi/install/lib/libjsoncpp.a
        libboost_system.a libboost_thread.a pthread crypto dl ssl z )
