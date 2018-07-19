#include "../include/Circuit.hpp"

void Circuit::readCircuit(const char* fileName)
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

        //allocate memory for the gates
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
            if (gates[i].gateType == 6) {
                nrOfXorGates++;
                // and / or gates
            }else if (gates[i].gateType == 12){
                nrOfNotGates++;
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

    myfile.close();
}

void Circuit::reArrangeCircuit() {


    int numOfGates = nrOfAndGates + nrOfXorGates + nrOfNotGates;
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

    gates = arrangedGates;
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
//Circuit * readCircuitFromFile(char * path)
//{
//	unsigned int gateAmount = 0;
//	unsigned int playerAmount = 0;
//	unsigned int wiresAmount = 0;
//	unsigned int lineCount = 1;
//	unsigned int playerCounter = 0;
//	unsigned int gateCounter = 0;
//    int numAndGates =  0;
//
//
//	unsigned int specialGatesAmount = 0;
//
//	unsigned int i;
//
//	unsigned int tempPlayerID;
//	unsigned int tempAmountOfBits;
//	unsigned int tempInput1;
//	unsigned int tempInput2;
//	unsigned int tempOutput;
//	unsigned int tempStatus;
//
//	char tempTT;
//	char tempFT;
//	char tempTF;
//	char tempFF;
//
//	char tempF;
//	char tempT;
//	TruthTable tempTruthTable;
//
//	unsigned int gotOutputsBits = false;
//
//
//	Circuit * circuitTR;
//	char lineBuff[STRING_BUFFER_SIZE];
//	char lineBuffCopy[STRING_BUFFER_SIZE];
//
//	FILE * circuitFile = fopen(path, "r");
//
//	if (circuitFile == NULL){
//		printf("Error: Bad file path...");
//		return NULL;
//	}
//	//read file, one line at a time
//	while (fgets(lineBuff, STRING_BUFFER_SIZE, circuitFile)){
//		//check for notes lines or empty lines. if found, continue.
//		strcpy(lineBuffCopy, lineBuff);
//		removeSpacesAndTabs(lineBuffCopy);
//		if (lineBuffCopy[0] == 0 || lineBuffCopy[0] == '#' || lineBuffCopy[0] == '\n') continue;
//
//		//will append in the first line and just one time.
//		if (gateAmount == 0){
//			if (sscanf(lineBuff, "%u %u %u", &gateAmount, &playerAmount, &wiresAmount) != 3){
//				printf("Error: First line in the file had to be in format of '<amount of gates> <amount of players>'\ne.g '32123 3'");
//				return NULL;
//			}
//			if (gateAmount <= 0){
//				printf("Error: Amount of gates needs to be more than 0");
//				return NULL;
//			}
//			// Init Circuit struct
//			circuitTR = (Circuit*)malloc(sizeof(Circuit));
//			circuitTR->gateArray = (Gate *)malloc(sizeof(Gate)*gateAmount);
//			circuitTR->playerArray = (pPlayer *)malloc(sizeof(pPlayer)*playerAmount);
//
//			circuitTR->allWires = (Wire *)malloc(sizeof(Wire)*wiresAmount);//(Irrelevant) +2 for one and zero
//			for (int i = 0; i < wiresAmount; i++)
//			{
//				circuitTR->allWires[i].number = i;
//
//			}
//
//			//circuitTR->amountOfGates = gateAmount;
//			circuitTR->numPlayers = playerAmount;
//			circuitTR->numWires = wiresAmount;
//
//
//
//		}
//		//players' input wires
//		else if (playerCounter < playerAmount){
//			if (sscanf(lineBuff, "P%u %u", &tempPlayerID, &tempAmountOfBits) == 2){
//				//Init new player....
//				circuitTR->playerArray[tempPlayerID].playerNumWires = tempAmountOfBits;	//
//				circuitTR->playerArray[tempPlayerID].playerWiresIndices = (unsigned int*)malloc(sizeof(unsigned int)*tempAmountOfBits);
//				circuitTR->playerArray[tempPlayerID].playerWires = (Wire**)malloc(sizeof(Wire*)*tempAmountOfBits);
//				for (i = 0; i < tempAmountOfBits; ++i) {
//					if (!fgets(lineBuff, STRING_BUFFER_SIZE, circuitFile)) { printf("Error: in line %u bit serial expected... but the file is ended.", lineCount); return NULL; }
//					lineCount++;
//
//					if (sscanf(lineBuff, "%u", &circuitTR->playerArray[tempPlayerID].playerWiresIndices[i]) != 1) {
//						printf("Error: in line %u expected for bit serial... ", lineCount); return NULL;
//					}
//					//pointer in player to input wire
//					circuitTR->playerArray[tempPlayerID].playerWires[i] = &circuitTR->allWires[circuitTR->playerArray[tempPlayerID].playerWiresIndices[i]];
//
//				}
//				playerCounter++;
//			}
//			else{
//				printf("Error: Player header expected. e.g P1 32");
//				return NULL;
//			}
//
//		}
//		//Output wires
//		else if (!gotOutputsBits){
//			gotOutputsBits = true;
//			if (sscanf(lineBuff, "Out %u", &tempAmountOfBits) == 1){
//				circuitTR->outputWires.playerNumWires = tempAmountOfBits;
//				circuitTR->outputWires.playerWiresIndices = (unsigned int*)malloc(sizeof(unsigned int)*tempAmountOfBits);
//				circuitTR->outputWires.playerWires = (Wire**)malloc(sizeof(Wire*)*tempAmountOfBits);
//				for (i = 0; i < circuitTR->outputWires.playerNumWires; ++i) {
//					if (!fgets(lineBuff, STRING_BUFFER_SIZE, circuitFile)) { printf("Error: in line %u bit serial expected... but the file is ended.", lineCount); return NULL; }
//					lineCount++;
//					if (sscanf(lineBuff, "%u", &circuitTR->outputWires.playerWiresIndices[i]) != 1) { printf("Error: in line %u expected for bit serial... ", lineCount); return NULL; }
//
//					circuitTR->outputWires.playerWires[i] = &circuitTR->allWires[circuitTR->outputWires.playerWiresIndices[i]];
//				}
//				circuitTR->numOfOutputWires = circuitTR->outputWires.playerNumWires;
//			}
//			else{
//				printf("Error: Outputs header expected. e.g O 32");
//				return NULL;
//			}
//		}
//		//Gates
//		else{
//			if ((tempStatus = sscanf(lineBuff, "%u %u %u %c%c%c%c\n", &tempInput1, &tempInput2, &tempOutput, &tempFF, &tempFT, &tempTF, &tempTT)) >= 7){
//
//				tempStatus = flagNone;
//				//create truthtable of gate
//				tempTruthTable = createTruthTablefFromChars(tempFF, tempFT, tempTF, tempTT);
//
//				circuitTR->gateArray[gateCounter] = GateCreator(tempInput1, tempInput2, tempOutput, tempTruthTable,circuitTR->allWires,gateCounter);
//				if (circuitTR->gateArray[gateCounter].flagNOMUL) specialGatesAmount++;
//
//				gateCounter++;
//			}
//
//			else if ((tempStatus = sscanf(lineBuff, "%u %u %c%c\n", &tempInput1, &tempOutput, &tempF, &tempT)) == 4)
//			{//not gates, make output wire negation of input wire. NOTE: not dealing with other gates (buffer, 1/0) currently.
//
//				//TODO
//
//				std::cout << "UNSUPPORTED GATE!!! " <<tempT<<tempF << std::endl;
//
//			}
//			else{
//				printf("Error: Gate header expected.. format: <inputWire1> <inputWire2(optional)> <ouputWire> <truthTable>");
//				return NULL;
//			}
//		}
//
//		lineCount++;
//	}
//
//	if (gateCounter < gateAmount) {
//		printf("Error: expected to %u gates, but got only %u...", gateAmount, gateCounter);
//		return NULL;
//	}
//
//	circuitTR->numGates = gateAmount;
//
//// 	for (int g = 0; g < circuitTR->numOfANDGates;g++)
//// 		_aligned_free(circuitTR->regularGates[g]->output->superseed);
//
//	fclose(circuitFile);
//
//	circuitTR->numOfInputWires = 0;
//	for (int p = 0; p < circuitTR->numPlayers; p++)
//	{
//		circuitTR->numOfInputWires += circuitTR->playerArray[p].playerNumWires;
//	}
//
//	auto numPublicElements = setFanOut(circuitTR);
//
//	return circuitTR;
//}
//
//void removeSpacesAndTabs(char* source)
//{
//    char* i = source;
//    char* j = source;
//    while (*j != 0)
//    {
//        *i = *j++;
//        if (*i != ' ' && *i != '\t')
//            i++;
//    }
//    *i = 0;
//}
//
//TruthTable createTruthTablefFromChars(char FF, char FT, char TF, char TT){
//    TruthTable TrueT;
//    TrueT.FF = charToBooleanValue(FF);
//    TrueT.FT = charToBooleanValue(FT);
//    TrueT.TF = charToBooleanValue(TF);
//    TrueT.TT = charToBooleanValue(TT);
//    TrueT.Y1 = TrueT.FF;
//    TrueT.Y2 = TrueT.FF ^ TrueT.TF;
//    TrueT.Y3 = TrueT.FF ^ TrueT.FT;
//    TrueT.Y4 = TrueT.FF ^ TrueT.FT ^ TrueT.TF ^ TrueT.TT;
//    return TrueT;
//}
//
//Gate GateCreator(const unsigned int inputBit1, const unsigned int inputBit2, const unsigned int outputBit, TruthTable TTable, Wire * wireArray, unsigned int number)
//{
//    Gate g;
//    g.gateNumber = number;
//
//    g.input1 = &wireArray[inputBit1];
//    g.input2 = &wireArray[inputBit2];
//    g.output = &wireArray[outputBit];
//    g.truthTable = TTable;
//
//    g.flagNOMUL = !TTable.Y4;//Check if it's a XOR/XNOR
//    //NOTE: currently not dealing with "trivial" gates
//    g.flagNOT = TTable.Y1;
//
//    if (!g.flagNOMUL)
//    {
//        if (TTable.FF + TTable.TF + TTable.FT + TTable.TT == 1)
//        {
//            //Shifted AND gate, compute shift
//            if (TTable.FF) g.sh = 3;
//            else if (TTable.FT) g.sh = 2;
//            else if (TTable.TF) g.sh = 1;
//            //shift of negation
//            if (wireArray[inputBit1].negation)
//                g.sh ^= 2;
//            if (wireArray[inputBit2].negation)
//                g.sh ^= 1;
//        }
//        else
//        {
//
//            printf("ERROR: Unsupported gate.\n");
//        }
//    }
//    else
//    {
//        if (TTable.Y2 + TTable.Y3 != 2)
//        {
//            printf("ERROR: Unsupported gate.\n");
//        }
//        else if (g.flagNOT)//XNOR gate
//        {
//            g.output->negation = !(g.input1->negation^g.input2->negation);
//        }
//        else//XOR gate
//        {
//            g.output->negation = g.input1->negation^g.input2->negation;
//        }
//
//    }
//
//    return g;
//}
//
//int setFanOut(Circuit* circuit)
//{
//    int maxfanout=0;
//    Gate* gate;
//    Wire* wire;
//    for (int g = 0; g < circuit->numGates; g++)
//    {
//        gate=&circuit->gateArray[g];
//        gate->input1->fanout++;
//        gate->input2->fanout++;
//
//        if (gate->input1->fanout>maxfanout)
//            maxfanout=gate->input1->fanout;
//        if (gate->input2->fanout>maxfanout)
//            maxfanout=gate->input2->fanout;
//    }
//
//    for (int w=0;w<circuit->numWires;w++)
//    {
//        wire=&circuit->allWires[w];
//        wire->usedFanouts=new int[maxfanout*maxfanout];
//        for (int i = 0; i < maxfanout; i++) {
//            wire->usedFanouts[i]=-1;
//        }
//    }
//    int numOfGenerators=0;
//    for (int g = 0; g < circuit->numGates; g++)
//    {
//        gate=&circuit->gateArray[g];
//        bool tmp=true;
//        int maxmin=0;
//        while (tmp)
//        {
//            tmp=false;
//            for (int i = 0; i < maxfanout*maxfanout; i++)
//            {
//                if (gate->input1->usedFanouts[i]==maxmin || gate->input2->usedFanouts[i]==maxmin)
//                {
//                    tmp=true;
//                    maxmin++;
//                }
//            }
//        }
//        gate->gateFanOutNum=maxmin;
//        if (maxmin>numOfGenerators)
//            numOfGenerators=maxmin;
//        for (int i = 0; i < maxfanout*maxfanout; i++)
//        {
//            if (gate->input2->usedFanouts[i]==-1)
//            {
//                gate->input2->usedFanouts[i]=maxmin;
//                break;
//            }
//        }
//        for (int i = 0; i < maxfanout*maxfanout; i++)
//        {
//            if (gate->input1->usedFanouts[i]==-1)
//            {
//                gate->input1->usedFanouts[i]=maxmin;
//                break;
//            }
//        }
//    }
//    for (int w=0;w<circuit->numWires;w++)
//    {
//        wire=&circuit->allWires[w];
//        delete[] wire->usedFanouts;
//    }
//
//    //4 generators for each gate
//    numOfGenerators++;
//    numOfGenerators*=4;
//    return numOfGenerators;
//}