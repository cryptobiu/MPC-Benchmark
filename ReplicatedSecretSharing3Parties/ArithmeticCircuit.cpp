#include "ArithmeticCircuit.h"

#include <fstream>      // std::ifstream




ArithmeticCircuit::ArithmeticCircuit()
{
}




ArithmeticCircuit::~ArithmeticCircuit()
{
}

void ArithmeticCircuit::readCircuit(const char* fileName)
{

    int inFan, outFan, input1, input2, output, type, numOfinputsForParty, numOfoutputsForParty;
    int numberOfGates, numberOfParties, numberOfOutputs, currentPartyNumber;
    int gateIndex = 0;
    ifstream myfile;


    myfile.open(fileName);


    int **partiesInputs;

    if (myfile.is_open())
    {

        myfile >> numberOfGates;//get the gates
        myfile >> numberOfParties;


        //inputs
        int *numOfInputsForEachParty = new int[numberOfParties];
        int **partiesInputs = new int*[numberOfParties];

        for (int j = 0; j<numberOfParties; j++) {
            myfile >> currentPartyNumber;

            myfile >> numOfinputsForParty;
            numOfInputsForEachParty[currentPartyNumber - 1] = numOfinputsForParty;

            partiesInputs[currentPartyNumber - 1] = new int[numOfInputsForEachParty[currentPartyNumber - 1]];

            for (int i = 0; i<numOfInputsForEachParty[currentPartyNumber - 1]; i++) {
                myfile >> partiesInputs[currentPartyNumber - 1][i];
            }
        }

        //outputs
        int *numOfOutputsForEachParty = new int[numberOfParties];
        int **partiesOutputs = new int*[numberOfParties];

        for (int j = 0; j<numberOfParties; j++) {
            myfile >> currentPartyNumber;

            myfile >> numOfoutputsForParty;
            numOfOutputsForEachParty[currentPartyNumber - 1] = numOfoutputsForParty;

            partiesOutputs[currentPartyNumber - 1] = new int[numOfOutputsForEachParty[currentPartyNumber - 1]];

            for (int i = 0; i<numOfOutputsForEachParty[currentPartyNumber - 1]; i++) {
                myfile >> partiesOutputs[currentPartyNumber - 1][i];
            }
        }




        //calculate the total number of inputs and outputs
        for (int i = 0; i<numberOfParties; i++) {
            nrOfInputGates += numOfInputsForEachParty[i];
            nrOfOutputGates += numOfOutputsForEachParty[i];
        }

        //allocate memory for the gates, We add one gate for the all-one gate whose output is always 1 and thus have a wire who is always 1 without the
        //involvement of the user. This will be useful to turn a NOT gate into a XORGate
        gates.resize(numberOfGates + nrOfInputGates + nrOfOutputGates);
     //   gates.resize(20);

        //create the input gates

        //create the input gates for each party
        for (int i = 0; i < numberOfParties; i++) {

            for (int j = 0; j < numOfInputsForEachParty[i];j++) {

                gates[gateIndex].gateType = 0;
                gates[gateIndex].input1 = -1;//irrelevant
                gates[gateIndex].input2 = -1;//irrelevant
                gates[gateIndex].output = partiesInputs[i][j];//the wire index
                gates[gateIndex].party = i + 1;

                gateIndex++;

            }
        }

        //go over the file and create gate by gate
        for (int i = nrOfInputGates; i<numberOfGates + nrOfInputGates; i++)
        {

            //get  each row that represents a gate
            myfile >> inFan;
            myfile >> outFan;
            myfile >> input1;
            myfile >> input2;
            myfile >> output;
            myfile >> type;

            gates[i].input1 = input1;
            gates[i].input2 = input2;
            gates[i].output = output;
            gates[i].gateType = type;
            gates[i].party = -1;//irrelevant

            if (type == 1) {
                nrOfAdditionGates++;
            }
            else if (type == 2) {
                nrOfMultiplicationGates++;
            }
            else if (type==4){
                nrOfRandomGates++;
            }
            else if (type==5){
                nrOfScalarMultGates++;
            }
            else if(type==6){
                nrOfSubtractionGates++;
            }

        }

        gateIndex = numberOfGates + nrOfInputGates;
        //create the output gates for each party
        for (int i = 0; i < numberOfParties; i++) {

            for (int j = 0; j < numOfOutputsForEachParty[i]; j++) {

                gates[gateIndex].gateType = 3;
                gates[gateIndex].input1 = partiesOutputs[i][j];
                gates[gateIndex].input2 = 0;//irrelevant
                gates[gateIndex].output = 0;//irrelevant
                gates[gateIndex].party = i + 1;

                gateIndex++;

            }
        }


        for (int i = 0; i < numberOfParties; ++i) {
            delete[] partiesInputs[i];
            delete[] partiesOutputs[i];
        }

        delete[] numOfInputsForEachParty;
        delete[] numOfOutputsForEachParty;
        delete[] partiesInputs;
        delete[] partiesOutputs;

    }
    myfile.close();
}

void ArithmeticCircuit::reArrangeCircuit() {


    int numOfGates = getNrOfGates();
    vector<TGate> arrangedGates(getNrOfGates());
    vector<long> newOrderedIndices(getNrOfGates());
    vector<bool> gateDoneArr(getNrOfGates());

    for(int i=0; i<gateDoneArr.size(); i++)
    {
        gateDoneArr[i] = false;
    }

    for(int i=0; i<nrOfInputGates; i++){
        gateDoneArr[i] = true;
        newOrderedIndices[i] = i;
    }

    for(int i=(getNrOfGates() - nrOfOutputGates); i<getNrOfGates(); i++){
        //gateDoneArr[i] = true;
        newOrderedIndices[i] = i;
    }



    int count = nrOfInputGates;
    int loopCount=0;


    while(count<(numOfGates-nrOfOutputGates)){

        loopCount=count;
        for(int k=(nrOfInputGates); k < (numOfGates - nrOfOutputGates); k++)
        {
            if(gates[k].gateType==5){
                if(!gateDoneArr[k] && gateDoneArr[gates[k].input1])
                {
                    //gateDoneArr[k] = true;

                    newOrderedIndices[count] = k;
                    count++;
                }
            }

            else if(!gateDoneArr[k] && gateDoneArr[gates[k].input1]
               && gateDoneArr[gates[k].input2])
            {
                //gateDoneArr[k] = true;

                newOrderedIndices[count] = k;
                count++;
            }

        }

        for(int i=loopCount; i<count; i++){
            gateDoneArr[newOrderedIndices[i]] = true;

        }

        layersIndices.push_back(loopCount);



    }
    layersIndices.push_back(count);

    //copy the right gates
    for(int k=0; k < (getNrOfGates() - nrOfOutputGates); k++) {
        arrangedGates[k] = gates[newOrderedIndices[k]];
    }

    //copy the output gates
    for(int k=(getNrOfGates() - nrOfOutputGates); k < getNrOfGates(); k++) {
        arrangedGates[k] = gates[k];
    }

    gates = move(arrangedGates);

}



