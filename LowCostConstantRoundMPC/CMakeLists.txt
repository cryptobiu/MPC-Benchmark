cmake_minimum_required(VERSION 3.5)
project(LowCostConstantRoundMPC)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -std=c++14 -mpclmul")


INCLUDE_DIRECTORIES(/usr/include/openssl $ENV{HOME}
        $ENV{HOME}/libscapi/lib/OTExtensionBristol
        $ENV{HOME}/libscapi/install/include
        $ENV{HOME}/libscapi/install/include/libOTe
        $ENV{HOME}/libscapi/install/include/libOTe/cryptoTools)

link_directories($ENV{HOME}/libscapi/install/lib $ENV{HOME}/libOTe/lib)

set(SOURCE_FILES main.cpp src/Party.cpp src/MPCCommunication.cpp src/Circuit.cpp src/TinyOT.cpp src/Utils.cpp)
add_executable(LowCostConstantRoundMPC ${SOURCE_FILES})

TARGET_LINK_LIBRARIES(LowCostConstantRoundMPC $ENV{HOME}/libscapi/libscapi.a
        gmp pthread crypto dl
        libblake2.a libOTe.a libcryptoTools.a libmiracl.a
        libboost_system.a)
