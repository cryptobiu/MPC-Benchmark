//
// Created by moriya on 04/01/17.
//

#include "../include/MPCCommunication.hpp"


vector<ProtocolPartyData*> MPCCommunication::setCommunication(boost::asio::io_service & io_service, osuCrypto::IOService & ios_ot, int id, int numParties, string configFile) {
cout<<"in communication"<<endl;

cout<<"num parties = "<<numParties<<endl;
    vector<ProtocolPartyData*> parties(numParties - 1);

    //open file
    ConfigFile cf(configFile);

    string portString, ipString;
    vector<int> ports(numParties);
    vector<string> ips(numParties);

    string address;
    int port;
    int counter = 0;
    for (int i = 0; i < numParties; i++) {
        portString = "party_" + to_string(i) + "_port";
        ipString = "party_" + to_string(i) + "_ip";

        //get partys IPs and ports data
        ports[i] = stoi(cf.Value("", portString));
        ips[i] = cf.Value("", ipString);
    }
cout<<"after read file"<<endl;
    SocketPartyData me, other;

    for (int i=0; i<numParties; i++){
        if (i < id) {// This party will be the receiver in the protocol
            cout<<" in connction loop. id = "<<id<<endl;
            me = SocketPartyData(boost_ip::address::from_string(ips[id]), ports[id] + i);
            cout<<"my port = "<<ports[id] + i<<endl;
            other = SocketPartyData(boost_ip::address::from_string(ips[i]), ports[i] + id - 1);
            cout<<"other port = "<<ports[i] + id - 1<<endl;

            shared_ptr<CommParty> channel = make_shared<CommPartyTCPSynced>(io_service, me, other);
            // connect to party one
            channel->join(500, 5000);
            cout<<"channel established"<<endl;
            //osuCrypto::IOService ios(0);
            address = ips[id];
            port = ports[id] + numParties - 1 + i;
            cout<<"address = "<<address << "port = "<<port<<endl;
            osuCrypto::Endpoint* ep0 = new osuCrypto::Endpoint(ios_ot, address, port, osuCrypto::EpMode::Server, "ep");
            osuCrypto::Channel otChannelServer = ep0->addChannel("chl0", "chl0");
cout<<"server ot connected"<<endl;

            address = ips[i];
            port = ports[i] + numParties - 1 + id -1;
            cout<<"address = "<<address << "port = "<<port<<endl;
            //osuCrypto::Endpoint* ep1 = new osuCrypto::Endpoint(ios_ot, address, port, osuCrypto::EpMode::Client, "ep1");
            osuCrypto::Channel otChannelClient = ep0->addChannel("chl1", "chl1");
//            cout<<"receiver port = "<<ports[i]+ numParties -2 + id<<endl;
//            OTExtensionBristolReceiver* receiver = new OTExtensionBristolReceiver(ips[i], ports[i]+ numParties -2 + id, true, nullptr);
//            cout<<"sender port = "<<ports[id] + numParties - 2 + i<<endl;
//            OTExtensionBristolSender* sender = new OTExtensionBristolSender(ports[id] + numParties - 1 + i, true, nullptr);

            parties[counter++] = new ProtocolPartyData(i, channel, ep0, otChannelServer, otChannelClient);
            cout<<"after set the party"<<endl;
        } else if (i>id) {// This party will be the sender in the protocol
            cout<<" in connction loop. id = "<<id<<endl;
            me = SocketPartyData(boost_ip::address::from_string(ips[id]), ports[id] + i - 1);
            cout<<"my port = "<<ports[id] + i - 1<<endl;
            other = SocketPartyData(boost_ip::address::from_string(ips[i]), ports[i] + id);
            cout<<"other port = "<< ports[i] + id<<endl;

            shared_ptr<CommParty> channel = make_shared<CommPartyTCPSynced>(io_service, me, other);
            // connect to party one
            channel->join(500, 5000);
            cout<<"channel established"<<endl;
            address = ips[i];
            port = ports[i]+ numParties -1 + id;
            cout<<"address = "<<address << "port = "<<port<<endl;
            //osuCrypto::IOService ios(0);
            osuCrypto::Endpoint* ep1 = new osuCrypto::Endpoint(ios_ot, address, port, osuCrypto::EpMode::Client, "ep");

            osuCrypto::Channel otChannelClient = ep1->addChannel("chl0", "chl0");
            cout<<"client ot connected"<<endl;
            address = ips[id];
            port = ports[id]+ numParties -1 + i - 1;
            cout<<"address = "<<address << "port = "<<port<<endl;
            //osuCrypto::IOService ios(0);
            //osuCrypto::Endpoint* ep0 = new osuCrypto::Endpoint(ios_ot, address, port, osuCrypto::EpMode::Server, "ep1");

            osuCrypto::Channel otChannelServer = ep1->addChannel("chl1", "chl1");
//            cout<<"sender port = "<<ports[id] + numParties - 2 + i<<endl;
//            OTExtensionBristolSender* sender = new OTExtensionBristolSender(ports[id] + numParties - 2 + i, true, nullptr);
//            cout<<"receiver port = "<<ports[i]+ numParties -1 + id<<endl;
//            OTExtensionBristolReceiver* receiver = new OTExtensionBristolReceiver(ips[i], ports[i]+ numParties -1 + id, true, nullptr);


            parties[counter++] = new ProtocolPartyData(i, channel, ep1, otChannelClient, otChannelServer);
            cout<<"after set the party"<<endl;
        }
    }

    return parties;

}