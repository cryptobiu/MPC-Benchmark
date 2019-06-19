#include <iostream>
#include "ExampleUdp.h"
#include "ExampleProtocol.h"

using namespace std;


int main(int argc, char* argv[])
{
    int partyId = stoi(argv[1]);
    int numOfParties = stoi(argv[2]);
    string partiesFile = argv[3];
    int dataSize = stoi(argv[4]);

//    ExampleUdp u(partyId, numOfParties, partiesFile, dataSize);
//    u.round();
    ExampleProtocol p(argc, argv);
    p.run();

    return 0;
}