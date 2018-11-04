cmake_minimum_required(VERSION 2.8)
project(SemiHonestYao)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O3 -std=c++14 -maes -mavx -mpclmul -mbmi2 -no-pie")

INCLUDE_DIRECTORIES($ENV{HOME} $ENV{HOME}/libscapi/install/include
        $ENV{HOME}/libscapi/lib/OTExtensionBristol
        $ENV{HOME}/libscapi/install/include
        $ENV{HOME}/libscapi/install/include/libOTe/cryptoTools/
        $ENV{HOME}/libscapi/install/include/libOTe)

set(SOURCE_FILES YaoParties.cpp App1.cpp)


link_directories($ENV{HOME}/libscapi/install/lib)


add_executable(SemiHonestYao ${SOURCE_FILES})

TARGET_LINK_LIBRARIES(SemiHonestYao
        $ENV{HOME}/libscapi/libscapi.a gmp gmpxx
        OTExtensionBristol libsimpleot.a libOTe.a libcryptoTools.a libmiracl.a
        boost_system boost_thread pthread crypto dl ssl z rt)
