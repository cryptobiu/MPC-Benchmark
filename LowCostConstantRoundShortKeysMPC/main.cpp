#include <iostream>
#include "include/Party.hpp"


int main(int argc, char* argv[])
{
    //Read the circuit from the file
//    CircuitConverter::convertBristolToScapi("Mult32.txt", "Mult32_scapi.txt", false);
//    Circuit circuit;
//    circuit.readCircuit(argv[2]);

    //Create the protocol party
    Party party(argc, argv);

//    chrono::high_resolution_clock::time_point start, end;
    vector<byte> output;

//    int preprocessTime = 0;
//    int onlineTime = 0, receiveTime = 0;

    //Run the protocol in a loop. We calculate the average time.
//    for (int i=0; i<times; i++) {
//        //initialize times in order the protocol times to be accurate, without any party wait to the others.
//        party.initTimes();
//
//        //offline phase
//        start = chrono::high_resolution_clock::now();
//        party.preprocess();
//        end = chrono::high_resolution_clock::now();
//        preprocessTime += std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
//        //outputFile << offlineTime << ",";
//
//        //read the inputs from a file
////        inputs = party.readInputs(argv[4]);
//
//        //initialize times again
//        party.initTimes();
//
//        //online phase
//        start = chrono::high_resolution_clock::now();
//        //For checking the online time,we execute only one party so the communication is commented out.
////        party.receiveInputsFromOtherParties(inputs);
//        party.simulateReceiveInputsFromOtherParties();
//        end = chrono::high_resolution_clock::now();
//        receiveTime += std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
//
//        start = chrono::high_resolution_clock::now();
//        output = party.localComputation();
//        end = chrono::high_resolution_clock::now();
//
//        onlineTime += std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
//
////        outputFile << onlineTime << endl;
//    }

    party.run();

    output = party.getOutput();
    cout<<"my output:"<<endl;
    for(int i=0; i<output.size(); i++) {
        cout << (int)output[i];
    }
    cout<<endl;

//    cout<<"preprocess took "<<preprocessTime/times << " milliseconds"<<endl;
//    cout<<"receive inputs took "<<receiveTime/times << " milliseconds"<<endl;
//    cout<<"online took "<<onlineTime/times << " milliseconds"<<endl;


}

