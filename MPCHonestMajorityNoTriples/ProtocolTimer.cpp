//
// Created by meital on 18/12/16.
//

#include "ProtocolTimer.h"


void ProtocolTimer::writeToFile() {

    ofstream myfile;
    myfile.open (fileName);
    myfile << "-------------Timings-----------.\n";
    //columns header
    myfile << "preparationPhase,inputPreparation,computationPhase, verificationPhase, outputPhase, totalTime,\n";

    for(int i=0; i<times; i++) {
        myfile << preparationPhaseArr[i] << ","
        << inputPreparationArr[i] << ","
        << computationPhaseArr[i] << ","
        << verificationPhaseArr[i] << ","
        << outputPhaseArr[i] << ","
        << totalTimeArr[i] << ",\n";

        cout<< "Times" <<preparationPhaseArr[i] << ","
        << inputPreparationArr[i] << ","
        << computationPhaseArr[i] << ","
        << verificationPhaseArr[i] << ","
        << outputPhaseArr[i] << ","
        << totalTimeArr[i] << ",\n";
    }

    myfile.close();

}

ProtocolTimer::ProtocolTimer(int times, string fileName) : fileName(fileName), times(times){


    preparationPhaseArr = new int[times];
    inputPreparationArr = new int[times];
    verificationPhaseArr = new int[times];
    computationPhaseArr= new int[times];
    outputPhaseArr= new int[times];
    totalTimeArr= new int[times];

}



