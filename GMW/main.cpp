#include <iostream>
#include "Circuit.h"
#include "GMWParty.h"

int main(int argc, char* argv[]) {

    GMWParty party(argc, argv);

    party.run();
    vector<byte> output = party.getOutput();

    cout << "circuit output:" << endl;
    for (int i = 0; i < output.size(); i++)
        cout << (int) output[i] << " ";

    cout << endl;
    return 0;
}

