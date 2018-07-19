#include <iostream>
#include "Circuit.h"
#include "GMWParty.h"

int main(int argc, char* argv[]) {


    string tmp = "init times";
    byte tmpBytes[20];


    GMWParty party(argc, argv);

    auto parties = party.getParties();

    for (int i = 0; i < parties.size(); i++) {
        if (parties[i]->getID() < party.getID()) {
            parties[i]->getChannel()->write(tmp);
            parties[i]->getChannel()->read(tmpBytes, tmp.size());
        } else {
            parties[i]->getChannel()->read(tmpBytes, tmp.size());
            parties[i]->getChannel()->write(tmp);
        }
    }

    party.run();
    vector<byte> output = party.getOutput();

    cout << "circuit output:" << endl;
    for (int i = 0; i < output.size(); i++)
    {
        cout << (int) output[i] << " ";
    }

    cout << endl;
    return 0;
}

