//
// Created by moriya on 15/2/17.
//
#include "YaoSEParty.h"


int main(int argc, char* argv[]) {

    YaoSEParty party(argc, argv);

    CmdParser parser;
    auto parameters = parser.parseArguments("", argc, argv);


    int runs = stoi(parser.getValueByKey(parameters, "internalIterationsNumber"));
    chrono::high_resolution_clock::time_point start, end;
    party.run();
    auto out = party.getOutput();
    if (out.size()  > 0) {

        cout << "result: " << endl;
        for (int i = 0; i < cf->n3; i++) {
            cout << (int)out[i] << " ";
        }
        cout << endl;
    }


    int offlineTime = 0, onlineTime = 0, loadTime = 0;

    for (int i=0; i<runs; i++){
        party.setIteration(i);
        party.sync();

        start = chrono::high_resolution_clock::now();
        party.runOffline();
        end = chrono::high_resolution_clock::now();
        offlineTime += std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

        start = chrono::high_resolution_clock::now();
        party.preOnline();
        end = chrono::high_resolution_clock::now();
        loadTime += std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        party.sync();

        start = chrono::high_resolution_clock::now();
        party.runOnline();
        end = chrono::high_resolution_clock::now();
        onlineTime += std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    }
    cout<<"running offline "<<runs<<" times took in average "<<offlineTime/runs << " millis"<<endl;
    cout<<" load "<<runs<<" times took in average "<<loadTime/runs << " millis"<<endl;
    cout<<"running online "<<runs<<" times took in average "<<onlineTime/runs << " millis"<<endl;
    out = party.getOutput();

    if (out.size()  > 0) {
        cout << "result: " << endl;
        for (int i = 0; i < cf->n3; i++) {
            cout << (int)out[i] << " ";
        }
        cout << endl;
    }


}