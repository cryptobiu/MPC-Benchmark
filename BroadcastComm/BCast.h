//
// Created by lior on 26/03/18.
//

#ifndef MPCCOMMUNICATION_H
#define MPCCOMMUNICATION_H

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

using namespace std;
using namespace boost::asio;
using random_bytes_engine = std::independent_bits_engine<
        std::default_random_engine, CHAR_BIT, unsigned char>;


class ProtocolPartyData {
private:
    int id;
    shared_ptr<CommParty> channel;  // Channel between this party to every other party in the protocol.

public:
    ProtocolPartyData() {}
    ProtocolPartyData(int id, shared_ptr<CommParty> channel)
            : id (id), channel(channel){
    }

    int getID() { return id; }
    shared_ptr<CommParty> getChannel() { return channel; }
};

class BCast :public Protocol, public HonestMajority, public MultiParty
{

public:
    BCast(int argc, char* argv []);
    ~BCast()
    {
        m_ioService.stop();
        delete m_measure;
    }
    bool hasOnline() { return false; }
    bool hasOffline()  { return false; }

    void setCommunication();
    void run();

private:
    Measurement *m_measure;
    int m_partyId;
    size_t m_numberOfParties;
    string m_partiesFilePath;
    int m_d;
    io_service  m_ioService;
    vector<shared_ptr<ProtocolPartyData>> m_channels;
    vector<byte> m_data;

    void createData();
};

#endif //MPCCOMMUNICATION_H
