cmake_minimum_required(VERSION 3.5)
project(MaliciousYaoSingleExecution)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -maes -mpclmul -msse4.1 -fPIC -march=native -o3")
cmake_policy(SET CMP0015 NEW)

INCLUDE_DIRECTORIES($ENV{HOME} $ENV{HOME}/libscapi/install/include
        ../../lib/OTExtensionBristol ../../lib/ ../../../)

link_directories(/usr/ssl/lib/ /usr/local/lib $ENV{HOME}/libscapi/install/lib )

set(SOURCE_FILES main.cpp YaoSEParty.cpp)
add_executable(MaliciousYaoSingleExecution ${SOURCE_FILES})

TARGET_LINK_LIBRARIES(MaliciousYaoSingleExecution $ENV{HOME}/libscapi/libscapi.a
        libjsoncpp.a
        libboost_system.a libboost_thread.a pthread crypto dl ssl z relic gmp emp-tool)
