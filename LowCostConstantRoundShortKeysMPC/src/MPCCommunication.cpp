//
// Created by moriya on 04/01/17.
//

#include "../include/MPCCommunication.hpp"


vector<ProtocolPartyData*> MPCCommunication::setCommunication(boost::asio::io_service & io_service, int id, int numParties, string configFile) {
//cout<<"in communication"<<endl;
//
//cout<<"num parties = "<<numParties<<endl;
//    vector<ProtocolPartyData*> parties(numParties - 1);
//
//    //open file
//    ConfigFile cf(configFile);
//
//    string portString, ipString;
//    vector<int> ports(numParties);
//    vector<string> ips(numParties);
//
//    string address;
//    int port;
//    int counter = 0;
//    for (int i = 0; i < numParties; i++) {
//        portString = "party_" + to_string(i) + "_port";
//        ipString = "party_" + to_string(i) + "_ip";
//
//        //get partys IPs and ports data
//        ports[i] = stoi(cf.Value("", portString));
//        ips[i] = cf.Value("", ipString);
//    }
//    SocketPartyData me, other;
//
//    for (int i=0; i<numParties; i++){
//        if (i < id) {// This party will be the receiver in the protocol
//            cout<<" in connction loop. id = "<<id<<endl;
//            me = SocketPartyData(boost_ip::address::from_string(ips[id]), ports[id] + i);
//            cout<<"my port = "<<ports[id] + i<<endl;
//            other = SocketPartyData(boost_ip::address::from_string(ips[i]), ports[i] + id - 1);
//            cout<<"other port = "<<ports[i] + id - 1<<endl;
//
//            shared_ptr<CommParty> channel = make_shared<CommPartyTCPSynced>(io_service, me, other);
//            // connect to party one
//            channel->join(500, 5000);
//            cout<<"channel established"<<endl;
//
//            parties[counter++] = new ProtocolPartyData(i, channel);//, ep0, otChannelServer, otChannelClient);
//            cout<<"after set the party"<<endl;
//        } else if (i>id) {// This party will be the sender in the protocol
//            cout<<" in connction loop. id = "<<id<<endl;
//            me = SocketPartyData(boost_ip::address::from_string(ips[id]), ports[id] + i - 1);
//            cout<<"my port = "<<ports[id] + i - 1<<endl;
//            other = SocketPartyData(boost_ip::address::from_string(ips[i]), ports[i] + id);
//            cout<<"other port = "<< ports[i] + id<<endl;
//
//            shared_ptr<CommParty> channel = make_shared<CommPartyTCPSynced>(io_service, me, other);
//            // connect to party one
//            channel->join(500, 5000);
//            cout<<"channel established"<<endl;
//            address = ips[i];
//            port = ports[i]+ numParties -1 + id;
//            cout<<"address = "<<address << "port = "<<port<<endl;
//
//            parties[counter++] = new ProtocolPartyData(i, channel);//, ep1, otChannelClient, otChannelServer);
//            cout<<"after set the party"<<endl;
//        }
//    }

    vector<ProtocolPartyData*> parties;
   return parties;

}