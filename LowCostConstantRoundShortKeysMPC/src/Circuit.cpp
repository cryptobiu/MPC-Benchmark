#include "../include/Circuit.hpp"

void Circuit::readCircuit(const char* fileName)
{
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

        //allocate memory for the gates
        gates.resize(numberOfGates);

        //go over the file and create gate by gate
        for (int i = 0; i<numberOfGates; i++)
        {
            //get  each row that represents a gate
            myfile >> gates[i].inFan;
            myfile >> gates[i].outFan;

            gates[i].inputIndices.resize(gates[i].inFan);

            for (int j=0; j<gates[i].inFan; j++){
                myfile >> gates[i].inputIndices[j];
            }

            myfile >> gates[i].outputIndex1;
            if (gates[i].outFan != 1)//a 1 input 2 output gate - split gate
            {
                myfile >> gates[i].outputIndex2;
            }
            myfile >> type;

            if (gates[i].inFan == 1 && gates[i].outFan == 1)//not gate
            {
                gates[i].gateType = 12;

            } else if (gates[i].inFan == 1 && gates[i].outFan == 2)//split gate
            {
                gates[i].gateType = 0;
            } else {
                gates[i].gateType = binaryTodecimal(type);
            }

            //Xor  gates
            if (gates[i].gateType == 6) {
                nrOfXorGates++;
                // and / or gates
            } else if (gates[i].gateType == 12){
                nrOfNotGates++;
                //Split gates
            } else if (gates[i].gateType == 0){
                nrOfSplitGates++;
            } else if (gates[i].gateType == 1 || gates[i].gateType == 7) {
                nrOfAndGates++;
            }

        }

        cout<<"num of and gates = "<<nrOfAndGates<<endl;
        cout<<"num of xor gates = "<<nrOfXorGates<<endl;
        cout<<"num of split gates = "<<nrOfSplitGates<<endl;
        reArrangeCircuit();
        checkOutputWires();
    }

    myfile.close();
}

void Circuit::reArrangeCircuit() {

    int numOfGates = nrOfAndGates + nrOfXorGates + nrOfNotGates + nrOfSplitGates;
    int numWires = getNrOfWires();
    vector<Gate> arrangedGates(numOfGates);
    vector<long> newOrderedIndices(numOfGates);
    vector<bool> gateDoneArr(numOfGates, false);
    vector<bool> isWireReady(numWires, false);
    for (int i=0; i<nrOfInput; i++){
        isWireReady[i] = true;
    }

    int count = 0;
    int loopCount=0;
    int andCounter = 0;
    Gate gate;
    bool isReady = true;
    while(count<numOfGates){
        loopCount=count;
        for(int k=0; k < numOfGates; k++)
        {
            gate = gates[k];
            //In case of not, split and xor gate, if the gate is ready to be computes, we can compute it and mark it as done.
            if (gate.gateType == 12){
                if (!gateDoneArr[k] && isWireReady[gate.inputIndices[0]]) {
                    newOrderedIndices[count] = k;
                    count++;
                    gateDoneArr[k] = true;
                    isWireReady[gate.outputIndex1] = true;
                }
            } if (gate.gateType == 0){
                if (!gateDoneArr[k] && isWireReady[gate.inputIndices[0]]) {
                    newOrderedIndices[count] = k;
                    count++;
                    gateDoneArr[k] = true;
                    isWireReady[gate.outputIndex1] = true;
                    isWireReady[gate.outputIndex2] = true;
                }
            } if (gate.gateType == 6){
                if (!gateDoneArr[k]){//} && isWireReady[gate.inputIndex1] && isWireReady[gate.inputIndex2]) {
                    for (int j=0; j<gate.inFan; j++){
                        if (!isWireReady[gate.inputIndices[j]]){
                            isReady = false;
                        }
                    }
                    if (isReady) {
                        newOrderedIndices[count] = k;
                        count++;
                        gateDoneArr[k] = true;
                        isWireReady[gate.outputIndex1] = true;
                    }
                    isReady = true;
                }
                //In case of and and or gates, if the gate is ready to be compute, we can compute it but the output will be ready just in the next layer.
            } else {
                if (!gateDoneArr[k] && isWireReady[gate.inputIndices[0]] && isWireReady[gate.inputIndices[1]]) {
                    newOrderedIndices[count] = k;
                    count++;
                }
            }

        }
        for(int i=loopCount; i<count; i++){
            gateDoneArr[newOrderedIndices[i]] = true;
            gate = gates[newOrderedIndices[i]];
            isWireReady[gate.outputIndex1] = true;
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

    gates = arrangedGates;
}

void Circuit::checkOutputWires(){
    outputWiresThatAreXorInputs.resize(getNrOfWires(), 0);

    Gate gate;
    int xorIndex = 1;
    //go over the file and create gate by gate
    for (int i = 0; i<getNrOfGates(); i++) {
        gate = gates[i];

        if (gate.gateType == 6){
            for (int j=0; j<gate.inFan; j++) {
                outputWiresThatAreXorInputs[gate.inputIndices[j]] = xorIndex;
            }
            xorIndex++;
        }
    }

    //go over the file and create gate by gate
    for (int i = 0; i<getNrOfGates(); i++) {
        gate = gates[i];

        if (gate.gateType == 12){
            if (outputWiresThatAreXorInputs[gate.outputIndex1] != 0) {
                    outputWiresThatAreXorInputs[gate.inputIndices[0]] = outputWiresThatAreXorInputs[gate.outputIndex1];
            }
        }
    }

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