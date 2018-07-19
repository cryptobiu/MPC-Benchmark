//
// Created by moriya on 04/01/17.
//

#include "BCast.h"

using namespace std;

BCast::BCast(int argc, char* argv []):
        Protocol("BCast", argc, argv)
{

    vector<string> names{"TestComm"};
    m_measure = new Measurement(*this, names);

    m_partyId = stoi(this->getParser().getValueByKey(arguments, "partyID"));
    m_numberOfParties = stoi(this->getParser().getValueByKey(arguments, "partiesNumber"));
    m_partiesFilePath = this->getParser().getValueByKey(arguments, "partiesFile");
    m_d = stoi(this->getParser().getValueByKey(arguments, "D"));
    setCommunication();

    // generate data
    createData();

}


void BCast::setCommunication()
{
    //open file
    ConfigFile cf(m_partiesFilePath);

    string portString, ipString;
    vector<int> ports(m_numberOfParties);
    vector<string> ips(m_numberOfParties);

    int counter = 0;

    for (int i = 0; i < m_numberOfParties; i++)
    {
        portString = "party_" + to_string(i) + "_port";
        ipString = "party_" + to_string(i) + "_ip";

        //get partys IPs and ports data
        ports[i] = stoi(cf.Value("", portString));
        ips[i] = cf.Value("", ipString);
    }

    SocketPartyData me, other;

    for (int i=0; i<m_numberOfParties; i++)
    {
        if (i < m_partyId) {// This party will be the receiver in the protocol

            me = SocketPartyData(boost_ip::address::from_string(ips[m_partyId]), ports[m_partyId] + i);
            cout<<"my port = "<<ports[m_partyId] + i<<endl;
            other = SocketPartyData(boost_ip::address::from_string(ips[i]), ports[i] + m_partyId - 1);
            cout<<"other port = "<<ports[i] + m_partyId - 1<<endl;

            shared_ptr<CommParty> channel = make_shared<CommPartyTCPSynced>(m_ioService, me, other);
            // connect to party one
            channel->join(500, 5000);
            cout<<"channel established"<<endl;

            m_channels.emplace_back(make_shared<ProtocolPartyData>(i, channel));
        }

        // This party will be the sender in the protocol
        else if (i>m_partyId)
        {
            me = SocketPartyData(boost_ip::address::from_string(ips[m_partyId]), ports[m_partyId] + i - 1);
            cout<<"my port = "<<ports[m_partyId] + i - 1<<endl;
            other = SocketPartyData(boost_ip::address::from_string(ips[i]), ports[i] + m_partyId);
            cout<<"other port = "<< ports[i] + m_partyId<<endl;

            shared_ptr<CommParty> channel = make_shared<CommPartyTCPSynced>(m_ioService, me, other);
            // connect to party one
            channel->join(500, 5000);
            cout<<"channel established"<<endl;

            m_channels.emplace_back(make_shared<ProtocolPartyData>(i, channel));
        }
    }
}

void BCast::createData()
{
    random_bytes_engine rbe;
    m_data.resize(m_d);
    generate(begin(m_data), end(m_data), ref(rbe));
}

void BCast::run()
{
    vector<vector<byte>> data(m_numberOfParties - 1); // save data from other parties

    for (size_t idx = 0; idx < data.size(); idx++)
        data[idx].resize(m_d);

    m_measure->startSubTask("TestComm", 1);

    for (size_t idx = 0; idx < m_channels.size(); idx++)
    {
        int peerId = m_channels[idx].get()->getID();
        if (m_partyId < peerId)
        {
            m_channels[idx].get()->getChannel().get()->write(m_data.data(), (int) m_data.size());

            m_channels[idx].get()->getChannel().get()->read(data[idx].data(), m_d);
        }

        else
        {
            m_channels[idx].get()->getChannel().get()->read(data[idx].data(), m_d);

            m_channels[idx].get()->getChannel().get()->write(m_data.data(), (int) m_data.size());
        }

        //sum the data
        vector<byte> sumData;
        for (int dataIdx = 0; dataIdx < data.size(); ++dataIdx)
        {
            byte tempSum = 0;
            for (int idx = 0; idx < m_numberOfParties; ++idx)
                tempSum += data[dataIdx][idx];

            sumData.emplace_back(tempSum);
        }
        m_measure->endSubTask("TestComm", 1);
    }
}