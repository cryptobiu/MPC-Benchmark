//
// Created by moriya on 04/01/17.
//

#ifndef GMW_MPCCOMMUNICATION_H
#define GMW_MPCCOMMUNICATION_H

#include "../../include/interactive_mid_protocols/OTBatch.hpp"
#include "../../include/interactive_mid_protocols/OTExtensionBristol.hpp"

class ProtocolPartyData {
private:
    int id;
    shared_ptr<CommParty> channel;  // Channel between this party to every other party in the protocol.
    OTBatchReceiver* receiver;      //Underlying ot receiver to use.
    OTBatchSender* sender;          //Underlying ot sender to use.

public:
    ProtocolPartyData() {}
    ProtocolPartyData(int id, shared_ptr<CommParty> channel, OTBatchSender* sender, OTBatchReceiver* receiver)
            : id (id), channel(channel), sender(sender), receiver(receiver) {
    }

    ~ProtocolPartyData(){
        delete sender;
        delete receiver;
    }

    int getID() { return id; }
    shared_ptr<CommParty> getChannel() { return channel; }
    OTBatchReceiver* getReceiver() { return receiver; }
    OTBatchSender* getSender() { return sender; }
};

class MPCCommunication {

public:
    static vector<shared_ptr<ProtocolPartyData>> setCommunication(boost::asio::io_service & io_service, int id, int numParties, string configFile);
};


#endif //GMW_MPCCOMMUNICATION_H
