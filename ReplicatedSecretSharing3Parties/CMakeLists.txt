cmake_minimum_required(VERSION 2.8)
project(ReplicatedSecretSharing3Parties)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -std=c++11 -mbmi2")


INCLUDE_DIRECTORIES($ENV{HOME}/ntl-9.10.0/include $ENV{HOME}
        $ENV{HOME}/libscapi/lib/OTExtensionBristol $ENV{HOME}/libscapi/install/include)

set(SOURCE_FILES AES_PRG.cpp HIM.cpp main.cpp VDM.cpp ArithmeticCircuit.cpp Protocol.cpp Protocol.h TemplateField.h
        TemplateField.cpp ProtocolTimer.cpp ZpGMPElement.cpp ZpMersenneIntElement.cpp
        ZpKaratsubaElement.cpp HashEncrypt.cpp ZpMersenneLongElement.cpp)


link_directories(/usr/ssl/lib/ $ENV{HOME}/libscapi/install/lib)

add_executable(ReplicatedSecretSharing3Parties ${SOURCE_FILES})

TARGET_LINK_LIBRARIES(ReplicatedSecretSharing3Parties
        $ENV{HOME}/libscapi/libscapi.a
        $ENV{HOME}/ntl-9.10.0/src/ntl.a
        gmp libboost_system.a pthread crypto dl)
