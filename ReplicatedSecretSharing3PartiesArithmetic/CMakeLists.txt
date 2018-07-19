cmake_minimum_required(VERSION 2.8)
project(ReplicatedSecretSharing3PartiesArithmetic)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -std=c++11 -maes -mpclmul -mbmi2")

INCLUDE_DIRECTORIES($ENV{HOME}/ntl-9.10.0/include $ENV{HOME} $ENV{HOME}/libscapi/install/include
        $ENV{HOME}/libscapi/lib/OTExtensionBristol)

set(SOURCE_FILES ProtocolParty.h ProtocolParty.cpp main.cpp HashEncrypt.cpp ProtocolTimer.cpp)

link_directories(/usr/ssl/lib/ $ENV{HOME}/libscapi/install/lib)


add_executable(ReplicatedSecretSharing3PartiesArithmetic ${SOURCE_FILES})

TARGET_LINK_LIBRARIES(ReplicatedSecretSharing3PartiesArithmetic $ENV{HOME}/ntl-9.10.0/src/ntl.a
	$ENV{HOME}/libscapi/libscapi.a gmp
	libboost_system.a libboost_thread.a pthread crypto dl ssl z)
