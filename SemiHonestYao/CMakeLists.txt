cmake_minimum_required(VERSION 2.8)
project(SemiHonestYao)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -std=c++14 -march=armv8-a -Wno-ignored-attributes -flax-vector-conversions")

INCLUDE_DIRECTORIES($ENV{HOME} $ENV{HOME}/libscapi/install/include
        $ENV{HOME}/libscapi/install/include $ENV{HOME}/OTExtension/
        $ENV{HOME}/OTExtension/extern/ENCRYPTO_utils/src/
        $ENV{HOME}/OTExtension/extern/ENCRYPTO_utils/extern/relic/include/)

set(SOURCE_FILES YaoParties.cpp App1.cpp)


link_directories($ENV{HOME}/OTExtension/ $ENV{HOME}/OTExtension/extern/ENCRYPTO_utils/src/
        $ENV{HOME}/OTExtension/extern/ENCRYPTO_utils/extern/relic/lib)


add_executable(SemiHonestYao ${SOURCE_FILES})

TARGET_LINK_LIBRARIES(SemiHonestYao
        otextension.a
        libencrypto_utils.a
        $ENV{HOME}/OTExtension/extern/ENCRYPTO_utils/extern/relic/lib/librelic.so
        $ENV{HOME}/libscapi/libscapi.a
        boost_system boost_thread pthread crypto dl ssl z rt gmp gmpxx)
