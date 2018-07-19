//
// Created by meital on 18/12/16.
//

#ifndef SECRET_SHARING_PROTOCOLTIMER_H
#define SECRET_SHARING_PROTOCOLTIMER_H

#include <iostream>
#include <fstream>
#include <string>
#include <chrono>

using namespace std;

class ProtocolTimer {

public:

    int *preparationPhaseArr;
    int* inputPreparationArr;
    int* computationPhaseArr;
    int* verificationPhaseArr;
    int* outputPhaseArr;
    int* totalTimeArr;

    string fileName;
    int times;

    ProtocolTimer(int times, string fileName);

    ~ProtocolTimer(){ delete[] preparationPhaseArr;
                      delete[] inputPreparationArr;
                      delete[] verificationPhaseArr;
                      delete[] computationPhaseArr;
                      delete[] outputPhaseArr;
                      delete[] totalTimeArr;}

    void writeToFile();

};


#endif //SECRET_SHARING_PROTOCOLTIMER_H
