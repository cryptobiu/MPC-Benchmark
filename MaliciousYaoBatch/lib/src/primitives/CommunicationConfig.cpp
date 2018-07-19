#include "../../include/primitives/CommunicationConfig.hpp"
/*
	Read configuration properties and set party and OT sockets.
	Set communication between the two partys.
	inputs:
			config_file - configuration file name.
			thisPartyNum - number of current party (1 or 2).
*/
CommunicationConfig::CommunicationConfig(string config_file, int thisPartyNum, boost::asio::io_service& io_service)
{
	//set party number
	this->partyNum = thisPartyNum;

	int numOfThread = CryptoPrimitives::getNumOfThreads();
	if (numOfThread == 0)
		numOfThread = 1;

	commParty.resize(numOfThread);
	me.resize(numOfThread);
	otherParty.resize(numOfThread);

	//open file
	ConfigFile cf(config_file);
	//get partys IPs and ports data
	int party_1_port = stoi(cf.Value("", "party_1_port"));
	int party_2_port = stoi(cf.Value("", "party_2_port"));
	string party_1_ip = cf.Value("", "party_1_ip");
	string party_2_ip = cf.Value("", "party_2_ip");

	//set partys IPs and ports to SockectPartyData
	for (int i = 0; i < numOfThread; i++) {
		if (this->partyNum == 1) {
			me[i] = SocketPartyData(IpAddress::from_string(party_1_ip), party_1_port);
			otherParty[i] = SocketPartyData(IpAddress::from_string(party_2_ip), party_2_port);
		}
		else {
			me[i] = SocketPartyData(IpAddress::from_string(party_2_ip), party_2_port);
			otherParty[i] = SocketPartyData(IpAddress::from_string(party_1_ip), party_1_port);
		}
		party_1_port += 2;
		party_2_port += 2;
	}
	
	for (int i = 0; i<numOfThread; i++) {
		commParty[i] = make_shared<CommPartyTCPSynced>(io_service, me[i], otherParty[i]);
	}
	
	//get OT IP and port
	int malicious_OT_port = stoi(cf.Value("", "malicious_OT_port"));
	string malicious_OT_address = cf.Value("", "malicious_OT_address");
	//set to SockectPartyData
	this->maliciousOTServer = make_shared<SocketPartyData>(IpAddress::from_string(malicious_OT_address), malicious_OT_port);
}

