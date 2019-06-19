//
// Created by liork on 3/19/19.
//

#ifndef EXAMPLEPROTOCOL_EXAMPLEUDP_H
#define EXAMPLEPROTOCOL_EXAMPLEUDP_H

#include <log4cpp/Category.hh>
#include <libscapi/include/comm/CommUDP.hpp>

using namespace std;

class ExampleUdp {
public:
    ExampleUdp(int partyId, int numOfParties, string partiesFile, int dataSize);
    void round();

private:
    int _numOfParties;
    int _partyId;
    int _dataSize;
    CommUDP _udp;
    vector< byte > _txData;
    vector< vector < byte > > _rxData;
};


#endif //EXAMPLEPROTOCOL_EXAMPLEUDP_H
