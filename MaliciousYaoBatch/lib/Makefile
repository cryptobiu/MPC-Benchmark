CXX=g++
SHARED_LIB_EXT:=.so
INCLUDE_ARCHIVES_START = -Wl,-whole-archive # linking options, we prefer our generated shared object will be self-contained.
INCLUDE_ARCHIVES_END = -Wl,-no-whole-archive
SHARED_LIB_OPT:=-shared

SLib           = MaliciousYao.a
CPP_FILES     := $(wildcard src/*/*.cpp)
CPP_FILES     += $(wildcard src/*/*/*.cpp)
C_FILES     := $(wildcard src/*/*.c)
OBJ_FILES     := $(patsubst src/%.cpp,obj/%.o,$(CPP_FILES))
OBJ_FILES     += $(patsubst src/%.c,obj/%.o,$(C_FILES))
OUT_DIR        = obj obj/CommitmentWithZkProofOfDifference obj/common obj/OfflineOnline/primitives obj/OfflineOnline/specs obj/OfflineOnline/subroutines obj/primitives
INC            = -I ../../../install/include/boost -I../../../../ -I../../../../libscapi/lib/NTL/unix/include -I../../../../libscapi/lib/ -I../../../../libscapi/lib/OTExtensionBristol -I../../../../libscapi/install/include
CPP_OPTIONS   := -std=c++11 $(INC) -pthread  -maes -mpclmul -Wno-unused-function -fPIC -O3 -w -msse4
$(COMPILE.cpp) = g++ -c $(CPP_OPTIONS) -o $@ $<
LINKER_OPTIONS = $(INCLUDE_ARCHIVES_START) ../../../../libscapi/libscapi.a ../../../../libscapi/install/lib/libOTExtensionBristol.a ../../../../libscapi/install/lib/libsimpleot.a -lpthread -lgmp -lcrypto -lssl -lboost_system -lntl \
-lboost_thread  -ldl $(INCLUDE_ARCHIVES_END)
LIBRARIES_DIR  = -L ../../../install/lib
LD_FLAGS =

all:: MaliciousYao
MaliciousYao:: directories $(SLib)
directories: $(OUT_DIR)

$(OUT_DIR):
	mkdir -p $(OUT_DIR)

$(SLib): $(OBJ_FILES)
	ar ru $@ $^
	ranlib $@

obj/primitives/%.o: src/primitives/%.cpp
	g++ -c $(CPP_OPTIONS) -o $@ $<
obj/OfflineOnline/primitives/%.o: src/OfflineOnline/primitives/%.cpp
	g++ -c $(CPP_OPTIONS) -o $@ $<
obj/OfflineOnline/specs/%.o: src/OfflineOnline/specs/%.cpp
	g++ -c $(CPP_OPTIONS) -o $@ $<
obj/OfflineOnline/subroutines/%.o: src/OfflineOnline/subroutines/%.cpp
	g++ -c $(CPP_OPTIONS) -o $@ $<
obj/common/%.o: src/common/%.cpp
	g++ -c $(CPP_OPTIONS) -o $@ $<
obj/CommitmentWithZkProofOfDifference/%.o: src/CommitmentWithZkProofOfDifference/%.cpp
	g++ -c $(CPP_OPTIONS) -o $@ $<

tests:: all
	$(Program)

clean:
	rm -rf obj
	rm *.a
