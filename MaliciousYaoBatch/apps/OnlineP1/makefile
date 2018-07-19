INC                       =  -I../../../install/include/boost -I../../../../../libscapi/lib -I../../../../../libscapi/install/include -I../../../../../libscapi/install/include/OTExtensionBristol -I../../../../../ -I../../
LIBS                      =  -L../../../../install/lib
INCLUDE_ARCHIVES_START    = -Wl,-whole-archive # linking options, we prefer our generated shared object will be self-contained.
INCLUDE_ARCHIVES_END      = -Wl,-no-whole-archive
LINKER_OPTIONS            = $(INCLUDE_ARCHIVES_START) $(LIBS) -lboost_log -lboost_system -lboost_thread -lboost_serialization  -lboost_filesystem ../../../../install/lib/libOTExtensionBristol.a ../../../../install/lib/libsimpleot.a -lrt -lntl -lcrypto -lssl -lpthread -ldl -lgmp -lgmpxx ../../../../install/lib/libjsoncpp.a ../../../../install/lib/libcryptoTools.a ../../../../install/lib/libOTe.a ../../../../install/lib/libmiracl.a ../../../../../libscapi/libscapi.a ../../lib/MaliciousYao.a  $(INCLUDE_ARCHIVES_END)
CXX                      = g++ -std=c++11 $(INC) -O3 -Wall -Wno-unused-function -maes

all: AppOnlineP1.out

AppOnlineP1.out:
	@echo "compiling!"
	$(CXX) AppOnlineP1.cpp -o $@ $(LINKER_OPTIONS)
clean:
	rm -f ./*.o
	rm -f ./*.out