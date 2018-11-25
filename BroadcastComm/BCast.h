//
// Created by lior on 26/03/18.
//
#include <gmp.h>
#include <gmpxx.h>
#include <random>
#include <climits>
#include <algorithm>
#include <functional>
#include <libscapi/include/comm/Comm.hpp>
#include <libscapi/include/infra/ConfigFile.hpp>
#include <libscapi/include/infra/Measurement.hpp>
#include <libscapi/include/cryptoInfra/SecurityLevel.hpp>
#include <libscapi/include/cryptoInfra/Protocol.hpp>
#include <libscapi/include/comm/MPCCommunication.hpp>

using namespace std;
using namespace boost::asio;
using random_bytes_engine = std::independent_bits_engine<
        std::default_random_engine, CHAR_BIT, unsigned char>;



class BCast :public MPCProtocol, public MultiParty {

public:
    BCast(int argc, char* argv []);

    bool hasOnline() { return true; }
    bool hasOffline()  { return false; }

    void runOnline();

private:
    int m_d;
     vector<byte> m_data;

    void createData();
};
