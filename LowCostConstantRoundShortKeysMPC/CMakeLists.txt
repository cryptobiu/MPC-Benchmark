cmake_minimum_required(VERSION 3.5)
project(LowCostConstantRoundShortKeysMPC)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -std=c++11 -mpclmul -maes -msse2 -msse4.1 -mavx -mavx2")


INCLUDE_DIRECTORIES(/usr/include/openssl $ENV{HOME} $ENV{HOME}/libscapi/install/include/OTExtensionBristol
        $ENV{HOME}/libscapi/install/include)

link_directories(/usr/ssl/lib/ $ENV{HOME}/libscapi/install/lib)

set(SOURCE_FILES main.cpp src/Party.cpp src/MPCCommunication.cpp src/Circuit.cpp src/Utils.cpp)

add_executable(LowCostConstantRoundShortKeysMPC ${SOURCE_FILES})

TARGET_LINK_LIBRARIES(LowCostConstantRoundShortKeysMPC $ENV{HOME}/libscapi/libscapi.a gmp
        libblake2.a libjsoncpp.a libboost_system.a libboost_thread.a pthread crypto dl ssl z)
