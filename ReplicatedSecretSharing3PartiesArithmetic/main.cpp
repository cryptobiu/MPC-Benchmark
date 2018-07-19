
#include <stdlib.h>
#include "ProtocolParty.h"
#include <chrono>

using namespace std::chrono;
/**
 * Three-Party Secure Computation Based on Replicated Secret Sharing
 * @param argc
 * @param argv[1] = id of parties (1,...,N)
 * @param argv[2] = path of inputs file
 * @param argv[3] = path of output file
 * @param argv[4] = path of circuit file
 * @param argv[5] = address
 * @param argv[6] = fieldType
 * @return
 */
int main(int argc, char* argv[])
{
    CmdParser parser;
    auto parameters = parser.parseArguments("", argc, argv);
    string fieldType(parser.getValueByKey(parameters, "fieldType"));
    int times = stoi(parser.getValueByKey(parameters, "internalIterationsNumber"));

    if(fieldType.compare("ZpMersenne") == 0)
    {
        ProtocolParty<ZpMersenneIntElement> protocol(argc, argv);
        auto t1 = high_resolution_clock::now();
        protocol.run();

        auto t2 = high_resolution_clock::now();

        auto duration = duration_cast<milliseconds>(t2-t1).count();
        cout << "time in milliseconds for " << times << " runs: " << duration << endl;

        cout << "end main" << '\n';
    }

    if(fieldType.compare("ZpMersenne61") == 0)
    {
        ProtocolParty<ZpMersenneLongElement> protocol(argc, argv);
        auto t1 = high_resolution_clock::now();
        protocol.run();

        auto t2 = high_resolution_clock::now();

        auto duration = duration_cast<milliseconds>(t2-t1).count();
        cout << "time in milliseconds for " << times << " runs: " << duration << endl;

        cout << "end main" << '\n';
    }

    return 0;
}
