//
// Created by moriya on 04/01/17.
//

#include "Circuit.h"
#include <unistd.h>
void Circuit::readCircuit(const string fileName)
{
cout<<fileName<<endl;

    int type, numOfinputsForParty, numOfoutputsForParty;
    int numberOfGates, currentPartyNumber;
    int gateIndex = 0;
    ifstream myfile;

    myfile.open(fileName);

    if (myfile.is_open())
    {
        myfile >> numberOfGates;//get the gates
        myfile >> numberOfParties;

        //inputs
        vector<int> numOfInputsForEachParty(numberOfParties);
        partiesInputs.resize(numberOfParties);

        for (int j = 0; j<numberOfParties; j++) {
            myfile >> currentPartyNumber;
            myfile >> numOfinputsForParty;

            numOfInputsForEachParty[currentPartyNumber - 1] = numOfinputsForParty;

            partiesInputs[currentPartyNumber - 1].resize(numOfInputsForEachParty[currentPartyNumber - 1]);

            for (int i = 0; i<numOfInputsForEachParty[currentPartyNumber - 1]; i++) {
                myfile >> partiesInputs[currentPartyNumber - 1][i];
            }
        }

        //outputs
        vector<int> numOfOutputsForEachParty(numberOfParties);
        partiesOutputs.resize(numberOfParties);

        for (int j = 0; j<numberOfParties; j++) {
            myfile >> currentPartyNumber;

            myfile >> numOfoutputsForParty;

            numOfOutputsForEachParty[currentPartyNumber - 1] = numOfoutputsForParty;
            partiesOutputs[currentPartyNumber - 1].resize(numOfOutputsForEachParty[currentPartyNumber - 1]);

            for (int i = 0; i<numOfOutputsForEachParty[currentPartyNumber - 1]; i++) {
                myfile >> partiesOutputs[currentPartyNumber - 1][i];
            }
        }

        //calculate the total number of inputs and outputs
        for (int i = 0; i<numberOfParties; i++) {
            nrOfInput += numOfInputsForEachParty[i];
            nrOfOutput += numOfOutputsForEachParty[i];
        }

        //allocate memory for the gates, We add one gate for the all-one gate whose output is always 1 and thus have a wire who is always 1 without the
        //involvement of the user. This will be useful to turn a NOT gate into a XORGate
        //gates.resize(numberOfGates + nrOfInputGates + nrOfOutputGates);
        gates.resize(numberOfGates);
        //   gates.resize(20);

        //create the input gates

        //create the input gates for each party
        /*for (int i = 0; i < numberOfParties; i++) {

            for (int j = 0; j < numOfInputsForEachParty[i];j++) {

                gates[gateIndex].gateType = 0;
                gates[gateIndex].inputIndex1 = -1;//irrelevant
                gates[gateIndex].inputIndex2 = -1;//irrelevant
                gates[gateIndex].outputIndex = partiesInputs[i][j];//the wire index

                gateIndex++;

            }
        }*/

        //go over the file and create gate by gate
        for (int i = 0; i<numberOfGates; i++)
        {
            //get  each row that represents a gate
            myfile >> gates[i].inFan;
            myfile >> gates[i].outFan;
            myfile >> gates[i].inputIndex1;

            if (gates[i].inFan != 1)//a 2 input 1 output gate - regualr gate, else we have a not gate
            {
                myfile >> gates[i].inputIndex2;
            }

            myfile >> gates[i].outputIndex;
            myfile >> type;

            if (gates[i].inFan == 1)//not gate
            {
                gates[i].gateType = 12;

            } else {
                gates[i].gateType = binaryTodecimal(type);
            }

            //Xor / not gates
            if (gates[i].gateType == 6 || gates[i].gateType == 12) {
                nrOfXorGates++;
            // and / or gates
            } else if (gates[i].gateType == 1 || gates[i].gateType == 7) {
                nrOfAndGates++;
            }

        }

        cout<<"num of and gates = "<<nrOfAndGates<<endl;
        cout<<"num of xor gates = "<<nrOfXorGates<<endl;

        reArrangeCircuit();

        //gateIndex = numberOfGates + nrOfInputGates;
        //create the output gates for each party
        /*for (int i = 0; i < numberOfParties; i++) {

            for (int j = 0; j < numOfOutputsForEachParty[i]; j++) {

                gates[gateIndex].gateType = 3;
                gates[gateIndex].input1 = partiesOutputs[i][j];
                gates[gateIndex].input2 = 0;//irrelevant
                gates[gateIndex].output = 0;//irrelevant
                gates[gateIndex].party = i + 1;

                gateIndex++;

            }
        }*/

    }
    cout<<"about to close"<<endl;
    myfile.close();
}

void Circuit::reArrangeCircuit() {


    int numOfGates = nrOfAndGates + nrOfXorGates;
    vector<Gate> arrangedGates(numOfGates);
    vector<long> newOrderedIndices(numOfGates);
    vector<int> layersAndCount(numOfGates);
    vector<bool> gateDoneArr(numOfGates, false);
    vector<bool> isWireReady(nrOfInput + numOfGates, false);
    for (int i=0; i<nrOfInput; i++){
        isWireReady[i] = true;
    }

    int count = 0;
    int loopCount=0;
    int andCounter = 0;
    Gate gate;

    while(count<numOfGates){
        loopCount=count;
        for(int k=0; k < numOfGates; k++)
        {
            gate = gates[k];
            //In case of not and xor gate, if the gate is ready to be computes, we can compute it and mark it as done.
            if (gate.gateType == 12){
                if (!gateDoneArr[k] && isWireReady[gate.inputIndex1]) {
                    newOrderedIndices[count] = k;
                    count++;
                    gateDoneArr[k] = true;
                    isWireReady[gate.outputIndex] = true;
                }
            }  if (gate.gateType == 6){
                if (!gateDoneArr[k] && isWireReady[gate.inputIndex1] && isWireReady[gate.inputIndex2]) {
                    newOrderedIndices[count] = k;
                    count++;
                    gateDoneArr[k] = true;
                    isWireReady[gate.outputIndex] = true;
                }
            //In case of and and or gates, if the gate is ready to be compute, we can compute it but the output will be ready just in the next layer.
            } else {
                if (!gateDoneArr[k] && isWireReady[gate.inputIndex1] && isWireReady[gate.inputIndex2]) {
                    newOrderedIndices[count] = k;
                    count++;
                }
            }

        }
        for(int i=loopCount; i<count; i++){
            gateDoneArr[newOrderedIndices[i]] = true;
            gate = gates[newOrderedIndices[i]];
            isWireReady[gate.outputIndex] = true;
            if (gate.gateType == 1 || gate.gateType == 7){
                andCounter++;
            }
        }
        depths.push_back(andCounter);
        andCounter = 0;
    }

    //copy the right gates
    for(int k=0; k < getNrOfGates(); k++) {
        arrangedGates[k] = gates[newOrderedIndices[k]];
    }

    gates = move(arrangedGates);
}




int Circuit::binaryTodecimal(int n){

    int output = 0;
    int pow = 1;

    //turns the string of the truth table that was taken as a decimal number into a number between 0 and 15 which represents the truth table
    //0 means the truth table of 0000 and 8 means 1000 and so on. The functions returns the decimal representation of the thruth table.
    for(int i=0; n > 0; i++) {

        if(n % 10 == 1) {

            output += pow;
        }
        n /= 10;

        pow = pow*2;
    }
    return output;
}