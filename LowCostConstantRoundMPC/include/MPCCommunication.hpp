//
// Created by moriya on 04/01/17.
//

#ifndef MPCCOMMUNICATION_H
#define MPCCOMMUNICATION_H

#include <libscapi/include/interactive_mid_protocols/OTBatch.hpp>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Endpoint.h>

class ProtocolPartyData {
private:
    int id;
    shared_ptr<CommParty> channel;  // Channel between this party to every other party in the protocol.
    osuCrypto::Endpoint* ep;
    osuCrypto::Channel otChannelFirst, otChannelSecond;

public:
    ProtocolPartyData() {}
    ProtocolPartyData(int id, shared_ptr<CommParty> channel, osuCrypto::Endpoint* ep, osuCrypto::Channel & otChannelFirst, osuCrypto::Channel & otChannelSecond)
            : id (id), channel(channel), ep(ep), otChannelFirst(otChannelFirst), otChannelSecond(otChannelSecond){
    }

    ~ProtocolPartyData(){
        otChannelFirst.close();
        otChannelSecond.close();
        ep->stop();
        delete ep;
    }

    int getID() { return id; }
    shared_ptr<CommParty> getChannel() { return channel; }
    osuCrypto::Channel & getOTChannelFirst() { return otChannelFirst; }
    osuCrypto::Channel & getOTChannelSecond() { return otChannelSecond; }
};

class MPCCommunication {

public:
    static vector<ProtocolPartyData*> setCommunication(boost::asio::io_service & io_service, osuCrypto::IOService & ios_ot, int id, int numParties, string configFile);
};


#endif //GMW_MPCCOMMUNICATION_H
