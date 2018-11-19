#include "../include/Party.hpp"

Party::Party(int argc, char* argv[])//int id, Circuit* circuit, string partiesFile, bool isLookup, int keySize)
        : Protocol("LowConstConstantRoundShortKeysMPC", argc, argv){ //id(id), circuit(circuit), isLookup(isLookup), keySize(keySize/8) {

    id = stoi(arguments["partyID"]);
    circuit.readCircuit(arguments["circuitFile"].c_str());
    isLookup = (arguments["isLookup"] =="true") ? true : false;
    keySize = stoi(arguments["keySize"])/8;

    times = stoi(arguments["internalIterationsNumber"]);

    vector<string> subTaskNames{"Preprocess", "Garble", "Online", "SimulateReceiveInputs", "localComputation"};
    timer = new Measurement("LowcostConstantRoundShortKeysMPC", id, circuit.getNrOfParties(), times, subTaskNames);
    //create the communication channels between all the parties
    parties = MPCCommunication::setCommunication(io_service, id, circuit.getNrOfParties(), arguments["partiesFile"]);
    numParties = circuit.getNrOfParties();

    prg = PrgFromOpenSSLAES((circuit.getNrOfWires()*2*numParties*keySize)/16 + 1, false);
    auto key = prg.generateKey(128);
    prg.setKey(key);

    //Print performance of each function to an output file
    if (id == 0) {
        string outputName = "Output_numParties=" + to_string(circuit.getNrOfParties()) + "_keySize=" + arguments["keySize"] +
                            "_isLookup=" + arguments["isLookup"] + ".csv";
        outputFile.open(outputName);
        outputFile << "Online phase" << endl;
    }

    utils.setParameters(id, parties, &prg, numParties - 1, &outputFile);

    //Fill the lookup tables with random bytes
    //auto keys = utils.coinTossing(2, 128);
    vector<vector<byte>> keys(2, vector<byte>(128));
    prg.getPRGBytes(keys[0], 0, 128);
    prg.getPRGBytes(keys[1], 0, 128);
    if (isLookup && id == 0) {
        lookupTableAnd.resize((pow(2, keySize + 1 + NumberOfBits(numParties))) * (numParties * keySize + 1));
        lookupTableSplit.resize((pow(2, keySize + 1 + NumberOfBits(numParties))) * numParties * keySize);
    }

    PrgFromOpenSSLAES tempPrg(lookupTableAnd.size() + lookupTableSplit.size());
    SecretKey prgkey(keys[0], "");
    tempPrg.setKey(prgkey);
    tempPrg.getPRGBytes(lookupTableAnd, 0, lookupTableAnd.size());
    tempPrg.getPRGBytes(lookupTableSplit, 0, lookupTableSplit.size());


    aes = EVP_CIPHER_CTX_new();
    cipher = EVP_aes_256_ecb();

    EVP_EncryptInit(aes, cipher, keys[1].data(), NULL);

    inputs = readInputs(arguments["inputsFile"]);
    otherInputFileName = arguments["otherInputsFile"];

}

void Party::initTimes(){
    string tmp = "init times";
    byte tmpBytes[20];
    for (int i = 0; i < parties.size(); i++) {
        if (parties[i]->getID() < id) {
            parties[i]->getChannel()->write(tmp);
            parties[i]->getChannel()->read(tmpBytes, tmp.size());
        } else {
            parties[i]->getChannel()->read(tmpBytes, tmp.size());
            parties[i]->getChannel()->write(tmp);
        }
    }
}

Party::~Party(){

    for (int i=0; i<parties.size(); i++){
        delete parties[i];
    }

    EVP_CIPHER_CTX_cleanup(aes);
    EVP_CIPHER_CTX_free(aes);



    if (id == 0) {
        delete [] garbleTableAnd;
        delete [] garbleTableSplit;

        outputFile.close();
    }

    io_service.stop();
    delete timer;
}

void Party::run() {
    for (iteration = 0; iteration<times; iteration++) {
        runOffline();
        timer->startSubTask(2, iteration);
        runOnline();
        timer->endSubTask(2, iteration);
    }

}

void Party::runOffline() {
    initTimes();
    timer->startSubTask(0, iteration);
    preprocess();
    timer->endSubTask(0, iteration);
}

void Party::runOnline() {
    initTimes();
    timer->startSubTask(3, iteration);
    simulateReceiveInputsFromOtherParties();
    timer->endSubTask(3, iteration);

    timer->startSubTask(4, iteration);
    localComputation();
    timer->endSubTask(4, iteration);
}

void Party::preprocess(){
    if (id == 0){
        timer->startSubTask(1, iteration);
        garble();
        timer->endSubTask(1, iteration);
    }

    else {
        receiveData();
    }
}

void Party::garble(){
    vector<byte> wireKeys0;
    vector<byte> wireKeys1;
//    auto start = chrono::high_resolution_clock::now();
    auto wiresLambdas = sampleLambdasAndKeys(wireKeys0, wireKeys1);
//    auto end = chrono::high_resolution_clock::now();
//    auto time = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
//    cout<<"sampleLambdasAndKeys took " << time << " nanoseconds"<<endl;

//    start = chrono::high_resolution_clock::now();
    generateGarblingTable(wiresLambdas, wireKeys0, wireKeys1);
//    end = chrono::high_resolution_clock::now();
//    time = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();

//    start = chrono::high_resolution_clock::now();
    sendOutputs(wiresLambdas);
    sendInputs(wiresLambdas);
//    end = chrono::high_resolution_clock::now();
//    time = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
//    cout<<"send inputs and outputs took " << time << " nanoseconds"<<endl;

//    start = chrono::high_resolution_clock::now();
    sendKeys(wireKeys0, wireKeys1);
//    end = chrono::high_resolution_clock::now();
//    time = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
//    cout<<"send keys took " << time << " nanoseconds"<<endl;
}


vector<byte> Party::sampleLambdasAndKeys(vector<byte> & wireKeys0, vector<byte> & wireKeys1) {

    //For each circuit-input wire u, sample λu ∈ {0,1} .
    int inputNumber = circuit.getNrOfInput();
//    int inputBytes = (inputNumber % 8 == 0 ? inputNumber / 8 : inputNumber / 8 + 1);
//    vector<byte> temp(inputNumber);
    vector<byte> wiresLambdas(circuit.getNrOfWires()); //Will hold all wires lambdas
    prg.getPRGBytes(wiresLambdas, 0, inputNumber);

    for (int i=0; i<inputNumber; i++){
        wiresLambdas[i] = wiresLambdas[i] % 2 == 0 ? 0 : 1;
    }

//    bitVector otherBits(circuit->getNrOfWires() - inputNumber);
//    wiresLambdas.append(otherBits);

    int allKeysSize = numParties * keySize;

    //For each circuit-input wire u, and for every i∈[n], sample ku,0 ∈ {0, 1}^l.
    wireKeys0.resize(circuit.getNrOfWires()*allKeysSize);  //Will hold all wires keys
    wireKeys1.resize(circuit.getNrOfWires()*allKeysSize);  //Will hold all wires keys
    //sample keys for input wires k0
    prg.getPRGBytes(wireKeys0, 0, inputNumber*allKeysSize);

    //sample a key for all wires except wires that are input for xor gates.
    vector<byte> sampledKeysForNotXorGates(circuit.getNrOfWires()*2*allKeysSize);
    //sample keys for input wires k0
    prg.getPRGBytes(sampledKeysForNotXorGates, 0, sampledKeysForNotXorGates.size());

    //For every g ∈ XOR and i∈[n] sample ∆ ig ∈ {0, 1}^l.
    vector<byte> xorGatesDeltas(circuit.getNrOfXorGates()*allKeysSize);  //Will hold all xor gates' deltas
    prg.getPRGBytes(xorGatesDeltas, 0, xorGatesDeltas.size());

    //get the output wires that wre input for a xor gate
    auto outputWiresThatAreXorInputs = circuit.getOutputWiresThatAreXorInputs();
    int nonXorIndex = 0;
    for (int i = 0; i < circuit.getNrOfInput(); i++) {
        if (outputWiresThatAreXorInputs[i] == 0) {
            memcpy(wireKeys1.data() + i*allKeysSize, sampledKeysForNotXorGates.data() + nonXorIndex*allKeysSize, allKeysSize);
            nonXorIndex++;
        } else {
            for (int j=0; j<allKeysSize; j++) {
                wireKeys1[i * allKeysSize + j] = wireKeys0[i * allKeysSize + j] ^ xorGatesDeltas[(outputWiresThatAreXorInputs[i] - 1) * allKeysSize + j];
            }
        }
    }

    //Passing topologically through all the gates g ∈ G = (AND ∪ XOR ∪ SPLIT) of the circuit.

    auto gates = circuit.getGates();

    int gatesSize = gates.size();
    Gate gate;
    int andIndex = 0, xorIndex = 0;

    //Prepare lambdas for and gates
    int andNumber = circuit.getNrOfAndGates();
//    int andBytes = (andNumber % 8 == 0 ? andNumber / 8 : andNumber / 8 + 1);
    vector<byte> andLambdas(andNumber);
    prg.getPRGBytes(andLambdas, 0, andNumber);
    for (int i=0; i<andNumber; i++){
        andLambdas[i] = andLambdas[i] % 2 == 0 ? 0 : 1;
    }

//    bitVector andLambdas(tempLambda.data(), andNumber);

    for (int i = 0; i < gatesSize; i++) {
        gate = gates[i];

        //If g ∈ XOR:
        //Set λ w = x∈I λ x .
        if (gate.gateType == 6) {//XOR gate

            wiresLambdas[gate.outputIndex1] = wiresLambdas[gate.inputIndices[0]];
            for (int j=1; j<gate.inFan; j++){
                wiresLambdas[gate.outputIndex1] = wiresLambdas[gate.outputIndex1] ^ wiresLambdas[gate.inputIndices[j]];
            }

            //For i ∈ [n], set k w,0= x∈I k x,0 and k w,1= k w,0 ⊕ ∆ ig.
            for (int j=0; j<allKeysSize; j++) {
                wireKeys0[gate.outputIndex1 * allKeysSize + j] = wireKeys0[gate.inputIndices[0] * allKeysSize + j];
                for (int k=1; k<gate.inFan; k++){
                    wireKeys0[gate.outputIndex1 * allKeysSize + j] ^= wireKeys0[gate.inputIndices[k] * allKeysSize + j];

                }
                wireKeys1[gate.outputIndex1 * allKeysSize + j] =
                            wireKeys0[gate.outputIndex1 * allKeysSize + j] ^ xorGatesDeltas[xorIndex * allKeysSize + j];

            }
            xorIndex++;
        } else if (gate.gateType == 12) {//NOT gate

            wiresLambdas[gate.outputIndex1] = wiresLambdas[gate.inputIndices[0]];

            for (int j=0; j<allKeysSize; j++) {
                wireKeys0[gate.outputIndex1 * allKeysSize + j] = wireKeys1[gate.inputIndices[0] * allKeysSize + j];
                wireKeys1[gate.outputIndex1 * allKeysSize + j] = wireKeys0[gate.inputIndices[0] * allKeysSize + j];

            }
        } else {

            //If g ∈ AND, sample λ w ∈ {0, 1}. If g ∈ SPLIT, set λ x = λ w for every x ∈ O.
            if (gate.gateType == 1 || gate.gateType == 7) { //AND gate
                wiresLambdas[gate.outputIndex1] = andLambdas[andIndex++];
            }
            if (gate.gateType == 0) { //Split gate
                wiresLambdas[gate.outputIndex1] = wiresLambdas[gate.inputIndices[0]];
                wiresLambdas[gate.outputIndex2] = wiresLambdas[gate.inputIndices[0]];
            }

            //For every x ∈ O, sample k x,0∈ {0, 1} l for i ∈ [n].
            //For i ∈ [n], if x ∈ O is input to an XOR gate g ′ , set k x,1= k x,0 ⊕ ∆ ig′.Otherwise sample kx,1∈{0,1}.
            memcpy(wireKeys0.data() + gate.outputIndex1*allKeysSize, sampledKeysForNotXorGates.data() + nonXorIndex*allKeysSize, allKeysSize);
            nonXorIndex ++;
            if (outputWiresThatAreXorInputs[gate.outputIndex1] == 0) {
                memcpy(wireKeys1.data() + gate.outputIndex1*allKeysSize, sampledKeysForNotXorGates.data() + nonXorIndex*allKeysSize, allKeysSize);
                nonXorIndex ++;
            } else {
                for (int j=0; j<allKeysSize; j++) {
                    wireKeys1[gate.outputIndex1 * allKeysSize + j] = wireKeys0[gate.outputIndex1 * allKeysSize + j] ^
                                                                        xorGatesDeltas[(outputWiresThatAreXorInputs[gate.outputIndex1] - 1) * allKeysSize + j];

                }
            }
            if (gate.gateType == 0) { //Split gate
                memcpy(wireKeys0.data() + gate.outputIndex2*allKeysSize, sampledKeysForNotXorGates.data() + nonXorIndex*allKeysSize, allKeysSize);
                nonXorIndex ++;
                if (outputWiresThatAreXorInputs[gate.outputIndex2] == 0) {
                    memcpy(wireKeys1.data() + gate.outputIndex2*allKeysSize, sampledKeysForNotXorGates.data() + nonXorIndex*allKeysSize, allKeysSize);
                    nonXorIndex ++;
                } else {
                    for (int j=0; j<allKeysSize; j++) {
                        wireKeys1[gate.outputIndex2 * allKeysSize + j] = wireKeys0[gate.outputIndex2 * allKeysSize + j] ^
                                    xorGatesDeltas[(outputWiresThatAreXorInputs[gate.outputIndex2] - 1) * allKeysSize + j];

                    }
                }
            }

        }
    }

    return wiresLambdas;
}

void Party::generateGarblingTable(const vector<byte> & wiresLambdas, vector<byte> & wireKeys0, vector<byte> & wireKeys1){

    int outputSize = numParties*keySize + 1; //size of the hash function, in bytes
    int counterSize = outputSize % 16 == 0 ? outputSize / 16 : outputSize / 16 + 1; //number of 128-bit in outputSize
    int allKeysSize = numParties*keySize; //size of the hash function, in bytes
    int splitCounterSize = allKeysSize % 16 == 0 ? allKeysSize / 16 : allKeysSize / 16 + 1; //number of 128-bit in outputSize

    garbleTableAnd = new byte[4*circuit.getNrOfAndGates()*outputSize];
    garbleTableSplit = new byte[2*circuit.getNrOfSplitGates()*2*allKeysSize];

    auto gates = circuit.getGates();
    int gatesSize = gates.size();
    Gate gate;
    byte a, b, c;
    byte *k0, *k1, *kc;
    int index, *intVal;
    byte* byteVal;
    int andIndex = 0, splitIndex = 0;
    byte* lookupPosition;

    byte* input = new byte[numParties*NUM_BYTES*counterSize];
    byte* output = new byte[numParties*NUM_BYTES*counterSize];
    byte* splitInput = new byte[numParties*NUM_BYTES*splitCounterSize*2];
    byte* splitOutput = new byte[numParties*NUM_BYTES*splitCounterSize*2];

    for (int i = 0; i < gatesSize; i++) {
        gate = gates[i];
        //If g ∈ AND, denote by a, b the external values of wires u and v and c = (a ⊕ λu) · (b ⊕ λv) ⊕ λw.
        //Compute and store the four rows of the garbling of g as:
        //g̃ a,b = ⊕i = 1, ..., n(H(i, b, k u,a) ⊕ H(i, a, k v,b))
        if (gate.gateType == 1 || gate.gateType == 7) { //AND gate

            for (int k = 0; k < 4; k++) {
                //Get the two input keys.
                if (k == 0) {
                    a = b = 0;
                    k0 = wireKeys0.data() + gate.inputIndices[0] * allKeysSize;
                    k1 = wireKeys0.data() + gate.inputIndices[1] * allKeysSize;
                } else if (k == 1) {
                    a = 0;
                    b = 1;
                    k0 = wireKeys0.data() + gate.inputIndices[0] * allKeysSize;
                    k1 = wireKeys1.data() + gate.inputIndices[1] * allKeysSize;
                } else if (k == 2) {
                    a = 1;
                    b = 0;
                    k0 = wireKeys1.data() + gate.inputIndices[0] * allKeysSize;
                    k1 = wireKeys0.data() + gate.inputIndices[1] * allKeysSize;
                } else if (k == 3) {
                    a = b = 1;
                    k0 = wireKeys1.data() + gate.inputIndices[0] * allKeysSize;
                    k1 = wireKeys1.data() + gate.inputIndices[1] * allKeysSize;
                }


                //calculate c = (a ⊕ λu) · (b ⊕ λv) ⊕ λw.
                c = ((a ^ wiresLambdas[gate.inputIndices[0]]) * (b ^ wiresLambdas[gate.inputIndices[1]])) ^
                    wiresLambdas[gate.outputIndex1];
                kc = (c == 0 ? (wireKeys0.data() + gate.outputIndex1 * allKeysSize) : (wireKeys1.data() +
                                                                                      gate.outputIndex1 * allKeysSize));

                lookupPosition = garbleTableAnd + andIndex * 4 * outputSize + (2 * a + b) * outputSize;

                if (isLookup) {
                    for (int j = 0; j < numParties; j++) {
                        //prepre the index to the lookup table - i, b, k u,a
                        index = j;
                        index = index << 1;
                        index = index | b;
                        index = index << 7;
                        index = index | k0[j * keySize];
                        for (int l = 1; l < keySize; l++) {
                            index = index << 8;
                            index = index | k0[j * keySize + l];
                        }
                        //copy the first lookup value to the garbled table
                        if (j == 0) {
                            memcpy(lookupPosition, lookupTableAnd.data() + index * outputSize, outputSize);
                        } else {
                            //xor the first lookup value to the garbled table
                            for (int l = 0; l < outputSize; l++) {
                                lookupPosition[l] ^= lookupTableAnd[index * outputSize + l];
                            }
                        }

                        //prepre the index to the lookup table - i, a, k v,b
                        index = j;
                        index = index << 1;
                        index = index | a;
                        index = index << 7;
                        index = index | k1[j * keySize];
                        for (int l = 1; l < keySize; l++) {
                            index = index << 8;
                            index = index | k1[j * keySize + l];
                        }

                        //xor the second lookup value to the garbled table
                        for (int l = 0; l < outputSize; l++) {
                            lookupPosition[l] ^= lookupTableAnd[index * outputSize + l];
                        }
                    }
                } else { //garbling using AES
                    for (int j = 0; j < numParties; j++) {
                        intVal = (int *) &input[j * NUM_BYTES * counterSize];
                        byteVal = &input[j * NUM_BYTES * counterSize];
                        //Prepare the input for the aes function.
                        for (int m = 0; m < counterSize; m++) {
                            //prepre the first aes input - i, b, k u,a, counter
                            intVal[0] = j;

                            byteVal[4] = a;
                            byteVal[5] = b;

//                            byteVal[6] = k0[j * keySize];
                            for (int l = 0; l < keySize; l++) {
                                byteVal[6 + l] = k0[j * keySize + l];
                                byteVal[6 + l + keySize] = k1[j * keySize + l];
//                                byteVal[6 + l] = 0;
//                                byteVal[6 + l + keySize] = 0;
                            }

                            byteVal[6 + 2*keySize] = m;

                            for (int l = 7 + 2*keySize; l<16; l++){
                                byteVal[l] = 0;
                            }
                            intVal+=4;
                            byteVal+=16;
                        }

//                        for (int m = 0; m < counterSize; m++) {
//                            //prepre the second aes input - i, b, k u,a, counter
//                            intVal[0] = j;
//                            intVal[1] = a;
//
//                            intVal[2] = 0 | k1[j * keySize];
//                            for (int l = 1; l < keySize; l++) {
//                                intVal[2] = intVal[2] << 8;
//                                intVal[2] = intVal[2] | k1[j * keySize + l];
//                            }
//
//                            intVal[3] = 0 | m;
//                            intVal+=4;
//                        }
                    }

                    //compute aes on the input
                    EVP_EncryptUpdate(aes, output, &index, input, numParties*NUM_BYTES*counterSize);

                    //get the output of the first party
                    memcpy(lookupPosition, output, outputSize);
//                    //xor with the second output of the first party
//                    for (int m = 0; m < outputSize; m++) {
//                        lookupPosition[m] ^= output[NUM_BYTES * counterSize + m];
//                    }
                    //xor with other outputs
                    for (int j = 1; j < numParties; j++) {

                        for (int m = 0; m < outputSize; m++) {
                            lookupPosition[m] ^= output[j*counterSize*NUM_BYTES + m];
//                            lookupPosition[m] ^= output[2*j*counterSize*NUM_BYTES + NUM_BYTES*counterSize + m];
                        }
                    }
                }

                //xor c and kw,c to the garbled table
                lookupPosition[0] ^= c;
                for (int j = 0; j < allKeysSize; j++) {
                    lookupPosition[j + 1] ^= kc[j];
                }
            }

            andIndex++;
        }

        if (gate.gateType == 0) { //split gate

            for (int c=0; c<2; c++) {

                if (c==0){
                    k0 = wireKeys0.data() + gate.inputIndices[0] * allKeysSize;
                } else {
                    k0 = wireKeys1.data() + gate.inputIndices[0] * allKeysSize;
                }

                lookupPosition = garbleTableSplit + splitIndex * 2 * (2 * allKeysSize) + c * (2 * allKeysSize);

                if (isLookup) {
                    for (int j = 0; j < numParties; j++) {
                        //prepre the index to the lookup table - i, 0, k w,c
                        index = j;
                        index = index << 1;
                        index = index | 0;
                        index = index << 7;
                        index = index | k0[j * keySize];
                        for (int l = 1; l < keySize; l++) {
                            index = index << 8;
                            index = index | k0[j * keySize + l];
                        }

                        if (j == 0) {
                            //Get the first output from the lookup table
                            memcpy(lookupPosition, lookupTableSplit.data() + index * allKeysSize, allKeysSize);
                        } else {
                            //xor the first lookup value to the garbled table
                            for (int l = 0; l < allKeysSize; l++) {
                                lookupPosition[l] ^= lookupTableSplit[index * allKeysSize + l];
                            }
                        }

                        //prepre the index to the lookup table - i, 0, k w,c
                        index = j;
                        index = index << 1;
                        index = index | 1;
                        index = index << 7;
                        index = index | k0[j * keySize];
                        for (int l = 1; l < keySize; l++) {
                            index = index << 8;
                            index = index | k0[j * keySize + l];
                        }

                        if (j == 0) {
                            //Get the second output from the lookup table
                            memcpy(lookupPosition + allKeysSize, lookupTableSplit.data() + index * allKeysSize, allKeysSize);
                        } else {
                            //xor the second lookup value to the garbled table
                            for (int l = 0; l < allKeysSize; l++) {
                                lookupPosition[allKeysSize + l] ^= lookupTableSplit[index * allKeysSize + l];
                            }
                        }
                    }
                } else {
                    for (int j = 0; j < numParties; j++) {
                        intVal = (int *) &splitInput[2 * j * NUM_BYTES * splitCounterSize];
                        //Prepare the input for the aes function.
                        for (int m = 0; m < splitCounterSize; m++) {
                            //prepare the first aes input - i, 0, k w,c
                            intVal[0] = j;
                            intVal[1] = 0;
                            intVal[2] = 0 | k0[j * keySize];
                            for (int l = 1; l < keySize; l++) {
                                intVal[2] = intVal[2] << 8;
                                intVal[2] = intVal[2] | k0[j * keySize + l];
                            }
                            intVal[3] = 0 | m;
                            intVal += 4;
                        }

                        for (int m = 0; m < splitCounterSize; m++) {
                            //prepare the second aes input - i, 1, k w,c
                            intVal[0] = j;
                            intVal[1] = 1;
                            intVal[2] = 0 | k0[j * keySize];
                            for (int l = 1; l < keySize; l++) {
                                intVal[2] = intVal[2] << 8;
                                intVal[2] = intVal[2] | k0[j * keySize + l];
                            }
                            intVal[3] = 0 | m;
                            intVal += 4;
                        }
                    }

                    //compute aes on the input
                    EVP_EncryptUpdate(aes, splitOutput, &index, splitInput, numParties*NUM_BYTES*splitCounterSize*2);

                    //get the output of the first party
                    memcpy(lookupPosition, splitOutput, allKeysSize);
                    memcpy(lookupPosition + allKeysSize, splitOutput + NUM_BYTES * splitCounterSize, allKeysSize);

                    //xor with other outputs
                    for (int j = 1; j < numParties; j++) {

                        for (int m = 0; m < allKeysSize; m++) {
                            lookupPosition[m] ^= splitOutput[2*j*splitCounterSize*NUM_BYTES + m];
                            lookupPosition[m + allKeysSize] ^= splitOutput[2*j*splitCounterSize*NUM_BYTES + NUM_BYTES*splitCounterSize + m];
                        }
                    }
                }
                //xor c, ku,c and kv,c to the garbled table
                kc = (c == 0 ? wireKeys0.data() + gate.outputIndex1*allKeysSize : wireKeys1.data() + gate.outputIndex1*allKeysSize);
                for( int j=0; j<allKeysSize; j++){
                    lookupPosition[j] ^= kc[j];
                }

                lookupPosition += allKeysSize;
                kc = (c == 0 ? wireKeys0.data() + gate.outputIndex2*allKeysSize : wireKeys1.data() + gate.outputIndex2*allKeysSize);
                for( int j=0; j<allKeysSize; j++){
                    lookupPosition[j] ^= kc[j];
                }


            }
            splitIndex++;
        }
    }

    delete [] output;
    delete [] input;
    delete [] splitOutput;
    delete [] splitInput;

}

void Party::sendOutputs(const vector<byte> & wireLambdas){

    outputLambdas.resize(circuit.getNrOfOutput());


    vector<int> outputIndices;
    int index = 0;

    //get all the output wires' sharings
    for (int i = 0; i < numParties; i++) {

        outputIndices = circuit.getPartyOutputs(i);
        for (int j = 0; j < outputIndices.size(); j++) {

            outputLambdas[index] = wireLambdas[outputIndices[j]];
            index++;
        }
    }

    //send the output for all the other parties
    //For checking the online time,we execute only one party so the communication is commented out.
//    utils.roundFunction(outputLambdas, 0);
}


void Party::receiveData(){

    //receive the output from the garbler
    outputLambdas.resize(circuit.getNrOfOutput());
    utils.roundFunction(outputLambdas, 0);

    //receive the input from the garbler
    auto size = circuit.getPartyInputs(id).size();
    vector<vector<byte>> allInputLambdas(1, vector<byte>(size));
    utils.roundFunction(allInputLambdas, 0);
    inputLambdas = allInputLambdas[0];

    vector<vector<byte>> keys(1, vector<byte>(circuit.getNrOfWires() * keySize));
    utils.roundFunction(keys, 0);
    inputKeys0 = keys[0];
    utils.roundFunction(keys, 0);
    inputKeys1 = keys[0];
}

void Party::sendInputs(const vector<byte> & wireLambdas){

    vector<int> inputIndices;
    allInputLambdas.resize(numParties - 1);

    //open the sharings of all input wires for each party.
    //save the sharings of this party's in put wires as allLambdaInputs.
    for (int i = 1; i < numParties; i++) {

        inputIndices = circuit.getPartyInputs(i);

        allInputLambdas[i-1].resize(inputIndices.size());

        for (int j = 0; j < inputIndices.size(); j++) {

            allInputLambdas[i-1][j] = wireLambdas[inputIndices[j]];
        }
    }

    inputIndices = circuit.getPartyInputs(id);
    inputLambdas.resize(inputIndices.size());
    for (int i = 0; i < inputIndices.size(); i++) {
        inputLambdas[i] = wireLambdas[inputIndices[i]];
    }

    //send the output for all the other parties
    //For checking the online time,we execute only one party so the communication is commented out.
//    utils.roundFunction(allInputLambdas, 0);

}

void Party::sendKeys(const vector<byte> & wireKeys0, const vector<byte> & wireKeys1){

    int numWires = circuit.getNrOfWires();
    //Set the garbler keys
    inputKeys0.resize(numWires * keySize);
    inputKeys1.resize(numWires * keySize);
    for (int j=0; j<numWires; j++){
        for (int l=0; l<keySize; l++) {
            inputKeys0[j * keySize + l] = wireKeys0[j * numParties * keySize + l];
            inputKeys1[j * keySize + l] = wireKeys1[j * numParties * keySize + l];
        }
    }

    //copy the other parties keys to a big array
    allkeys0.resize(numParties-1);
    allkeys1.resize(numParties-1);
    for (int i = 1; i < numParties; i++) {
        allkeys0[i-1].resize(numWires * keySize);
        allkeys1[i-1].resize(numWires * keySize);
        for (int j=0; j<numWires; j++){
            for (int l=0; l<keySize; l++) {
                allkeys0[i - 1][j * keySize + l] = wireKeys0[j * numParties * keySize + i * keySize + l];
                allkeys1[i - 1][j * keySize + l] = wireKeys1[j * numParties * keySize + i * keySize + l];
            }
        }

    }

    //send the output for all the other parties
    //For checking the online time,we execute only one party so the communication is commented out.
//    utils.roundFunction(allkeys0, 0);
//    utils.roundFunction(allkeys1, 0);

}

vector<byte> Party::readInputs(string inputFileName) {
    //Read the input from the given input file
    ifstream myfile;
    int inputSize = circuit.getPartyInputs(id).size();
    vector<byte> inputs(inputSize);
    int inputBit;
    myfile.open(inputFileName);

    for (int i = 0; i < inputSize; i++) {
        myfile >> inputBit;
        inputs[i] = inputBit;
    }
    myfile.close();
    return inputs;
}

void Party::receiveInputsFromOtherParties(const vector<byte> & inputs) {

    //For all input wires w with input from P i , party P i computes Λ w = ρ i,w ⊕ λ w , where ρ i,w is P i ’s input to C f
    //on wire w, and λ w was obtained from F Prepocessing.
    int myInputsSize = inputs.size();
    vector<vector<byte>> inputsBits(numParties);
    auto inputsIndices = circuit.getPartyInputs(id);

    int numWires = circuit.getNrOfWires();
    publicValues = new byte[numWires];

    //Compute  Λ w = ρ i,w ⊕ λ w for each input wire of this party
    inputsBits[id].resize(myInputsSize);
    for (int i = 0; i < myInputsSize; i++) {
        inputsBits[id][i] = inputs[i] ^ inputLambdas[i];
        publicValues[inputsIndices[i]] = inputsBits[id][i];
    }


    //Then, Pi broadcasts the public value Λ w to all parties.
    for (int i = 0; i < numParties; i++) {
        if (id == i) {
            utils.broadcast(i, inputsBits[id].data(), inputsBits[id].size());
        } else {
            inputsIndices = circuit.getPartyInputs(i);
            inputsBits[i].resize(inputsIndices.size());
            utils.broadcast(i, inputsBits[i].data(), inputsBits[i].size());

            for (int j = 0; j < inputsIndices.size(); j++) {
                publicValues[inputsIndices[j]] = inputsBits[i][j];
            }
        }
    }


    int inputSize = circuit.getNrOfInput();
    vector<vector<byte>> inputKeys(numParties, vector<byte>(inputSize * keySize));
    computeKeys.resize(numWires * numParties * keySize);
    //For all input wires w, each party Pi broadcasts the key kw associated to Λw.
    for (int i = 0; i < inputSize; i++) {
        if (publicValues[i] == 0) {
            for (int l = 0; l < keySize; l++) {
                inputKeys[id][i * keySize + l] = inputKeys0[i * keySize + l];
            }
        } else {
            for (int l = 0; l < keySize; l++) {
                inputKeys[id][i * keySize + l] = inputKeys1[i * keySize + l];
            }
        }
        for (int l = 0; l < keySize; l++) {
            computeKeys[i * numParties * keySize + l] = inputKeys[id][i * keySize + l];
        }
    }

    for (int i = 0; i < numParties; i++) {
        if (id == i) {
            utils.broadcast(i, inputKeys[id].data(), inputKeys[id].size());
        } else {
            utils.broadcast(i, inputKeys[i].data(), inputKeys[i].size());

            for (int j = 0; j < inputSize; j++) {
                for (int l = 0; l < keySize; l++) {
                    computeKeys[j * numParties * keySize + i * keySize + l] = inputKeys[i][j * keySize + l];
                }
            }
        }
    }

    openGarble();
}

void Party::simulateReceiveInputsFromOtherParties() {

    //For all input wires w with input from P i , party P i computes Λ w = ρ i,w ⊕ λ w , where ρ i,w is P i ’s input to C f
    //on wire w, and λ w was obtained from F Prepocessing.
    int inputsSize;
    vector<vector<byte>> inputsBits(numParties);
    vector<int> inputsIndices;

    int numWires = circuit.getNrOfWires();
    publicValues = new byte[numWires];
    vector<byte> otherInputs;

    for (int j=0; j<numParties; j++) {

        inputsIndices = circuit.getPartyInputs(j);
        inputsSize =  inputsIndices.size();

        //Compute  Λ w = ρ i,w ⊕ λ w for each input wire of this party
        inputsBits[j].resize(inputsSize);

        if (j == 0) {
            for (int i = 0; i < inputsSize; i++) {
                inputsBits[j][i] = inputs[i] ^ inputLambdas[i];
                publicValues[inputsIndices[i]] = inputsBits[j][i];
            }
        } else {
            otherInputs = readInputs(otherInputFileName);
            for (int i = 0; i < inputsSize; i++) {
                inputsBits[j][i] = otherInputs[i] ^ allInputLambdas[j-1][i];
                publicValues[inputsIndices[i]] = inputsBits[j][i];
            }
        }
    }


    //Then, Pi broadcasts the public value Λ w to all parties.
//    for (int i = 0; i < numParties; i++) {
//        if (id == i) {
//            utils.broadcast(i, inputsBits[id].data(), inputsBits[id].size());
//        } else {
//            inputsIndices = circuit->getPartyInputs(i);
//            inputsBits[i].resize(inputsIndices.size());
//            utils.broadcast(i, inputsBits[i].data(), inputsBits[i].size());
//
//            for (int j = 0; j < inputsIndices.size(); j++) {
//                publicValues[inputsIndices[j]] = inputsBits[i][j];
//            }
//        }
//    }


    int inputSize = circuit.getNrOfInput();
    vector<vector<byte>> inputKeys(numParties, vector<byte>(inputSize * keySize));
    computeKeys.resize(numWires * numParties * keySize);
    //For all input wires w, each party Pi broadcasts the key kw associated to Λw.
    for (int j=0; j<numParties; j++) {
        for (int i = 0; i < inputSize; i++) {

            if (j==0) {
                if (publicValues[i] == 0) {
                    for (int l = 0; l < keySize; l++) {
                        inputKeys[j][i * keySize + l] = inputKeys0[i * keySize + l];
                    }
                } else {
                    for (int l = 0; l < keySize; l++) {
                        inputKeys[j][i * keySize + l] = inputKeys1[i * keySize + l];
                    }
                }
            } else {
                if (publicValues[i] == 0) {
                    for (int l = 0; l < keySize; l++) {
                        inputKeys[j][i * keySize + l] = allkeys0[j-1][i * keySize + l];
                    }
                } else {
                    for (int l = 0; l < keySize; l++) {
                        inputKeys[j][i * keySize + l] = allkeys1[j-1][i * keySize + l];
                    }
                }
            }
            for (int l = 0; l < keySize; l++) {
                computeKeys[i * numParties * keySize + j* keySize + l] = inputKeys[j][i * keySize + l];
            }
        }
    }

//    for (int i = 0; i < numParties; i++) {
//        if (id == i) {
//            utils.broadcast(i, inputKeys[id].data(), inputKeys[id].size());
//        } else {
//            utils.broadcast(i, inputKeys[i].data(), inputKeys[i].size());
//
//            for (int j = 0; j < inputSize; j++) {
//                for (int l = 0; l < keySize; l++) {
//                    computeKeys[j * numParties * keySize + i * keySize + l] = inputKeys[i][j * keySize + l];
//                }
//            }
//        }
//    }

    openGarble();
}

vector<byte> Party::localComputation(){

    if (id == 0) {
        //compute the circuit locally.
//        start = chrono::high_resolution_clock::now();
        localComputeCircuit(computeKeys, publicValues);
//        end = chrono::high_resolution_clock::now();
//        time = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
//        cout<<"local computation took " << time << " nanoseconds"<<endl;


//        start = chrono::high_resolution_clock::now();
        output = computeOutput(computeKeys, publicValues);
//        end = chrono::high_resolution_clock::now();
//        time = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
//        cout<<"compute output took " << time << " nanoseconds"<<endl;
    }
    delete [] publicValues;
    return output;
}

void Party::openGarble(){

}

void Party::localComputeCircuit(vector<byte> & computeKeys, byte* publicValues){

    int outputSize = numParties*keySize + 1; //size of the hash function, in bytes
    int counterSize = outputSize % 16 == 0 ? outputSize / 16 : outputSize / 16 + 1; //number of 128-bit in outputSize
    int allKeysSize = numParties*keySize; //size of the hash function, in bytes
    int splitCounterSize = allKeysSize % 16 == 0 ? allKeysSize / 16 : allKeysSize / 16 + 1; //number of 128-bit in outputSize

//    vector<Gate> gates = circuit->getGates();
    Gate gate;
    int gatesSize = circuit.getGates().size();

    int entry, index, *intVal;
    int size, andIndex = 0, splitIndex = 0;
    byte* splitKey = new byte[2*allKeysSize];
    byte* andKey = new byte[outputSize];

    byte* input = new byte[numParties*NUM_BYTES*counterSize];
    byte* output = new byte[numParties*NUM_BYTES*counterSize];
    byte* splitInput = new byte[numParties*NUM_BYTES*splitCounterSize*2];
    byte* splitOutput = new byte[numParties*NUM_BYTES*splitCounterSize*2];

    byte* temp, *temp2, *temp0, *temp1,  *byteVal;
    /*
     * Passing through the circuit topologically, the parties can now locally compute the following operations for
     * each gate g.
     */
    for (int i=0; i<gatesSize; i++){
        gate = circuit.getGates()[i];

        if (gate.gateType == 0) {//SPLIT gate

            publicValues[gate.outputIndex1] = publicValues[gate.inputIndices[0]];
            publicValues[gate.outputIndex2] = publicValues[gate.inputIndices[0]];

            entry = splitIndex * 2 * (2 * allKeysSize) + publicValues[gate.inputIndices[0]] * (2 * allKeysSize);

            //copy g̃Λw
            memcpy(splitKey, garbleTableSplit + entry, 2*allKeysSize);

            if (isLookup) {
                for (int j = 0; j < numParties; j++) {
                    index = j;
                    index = index << 1;
                    index = index | 0;
                    index = index << 7;
                    temp = &computeKeys[gate.inputIndices[0] * allKeysSize + j * keySize];
//                    index = index | computeKeys[gate.inputIndices[0] * allKeysSize + j * keySize];
//                    for (int l = 1; l < keySize; l++) {
//                        index = index << 8;
//                        index = index | computeKeys[gate.inputIndices[0] * allKeysSize + j * keySize + l];
//                    }
                    index = index | *temp;
                    temp++;
                    for (int l = 1; l < keySize; l++, temp++) {
                        index = index << 8;
                        index = index | *temp;
                    }

                    //xor the first lookup value to the garbled table
                    for (int l = 0; l < allKeysSize; l++) {
                        splitKey[l] ^= lookupTableSplit[index * allKeysSize + l];
                    }

                    index = j;
                    index = index << 1;
                    index = index | 1;
                    index = index << 7;
                    temp = &computeKeys[gate.inputIndices[0] * allKeysSize + j * keySize];
                    index = index | *temp;
                    temp++;
                    for (int l = 1; l < keySize; l++, temp++) {
                        index = index << 8;
                        index = index | *temp;
                    }
//                    index = index | computeKeys[gate.inputIndices[0] * allKeysSize + j * keySize];
//                    for (int l = 1; l < keySize; l++) {
//                        index = index << 8;
//                        index = index | computeKeys[gate.inputIndices[0] * allKeysSize + j * keySize + l];
//                    }

                    //xor the first lookup value to the garbled table
                    for (int l = 0; l < allKeysSize; l++) {
                        splitKey[l + allKeysSize] ^= lookupTableSplit[index * allKeysSize + l];
                    }
                }
            } else {
                for (int j = 0; j < numParties; j++) {
                    //Prepare the input for the aes function.
                    intVal = (int *) &splitInput[2 * j * NUM_BYTES * splitCounterSize];
                    for (int m = 0; m < splitCounterSize; m++) {
                        //prepre the first aes input - i, b, k u,a, counter
                        intVal[0] = j;
                        intVal[1] = 0;
                        temp = &computeKeys[gate.inputIndices[0] * allKeysSize + j * keySize];
                        intVal[2] = 0 | *temp;
                        temp++;
                        for (int l = 1; l < keySize; l++, temp++) {
                            intVal[2] = intVal[2] << 8;
                            intVal[2] = intVal[2] | *temp;
                        }
//                        intVal[2] = 0 | computeKeys[gate.inputIndices[0] * allKeysSize + j * keySize];
//                        for (int l = 1; l < keySize; l++) {
//                            intVal[2] = intVal[2] << 8;
//                            intVal[2] = intVal[2] | computeKeys[gate.inputIndices[0] * allKeysSize + j * keySize + l];
//                        }
                        intVal[3] = 0 | m;
                        intVal += 4;
                    }

                    for (int m = 0; m < splitCounterSize; m++) {
                        intVal[0] = j;
                        intVal[1] = 1;
                        temp = &computeKeys[gate.inputIndices[0] * allKeysSize + j * keySize];
                        intVal[2] = 0 | *temp;
                        temp++;
                        for (int l = 1; l < keySize; l++, temp++) {
                            intVal[2] = intVal[2] << 8;
                            intVal[2] = intVal[2] | *temp;
                        }
//                        intVal[2] = 0 | computeKeys[gate.inputIndices[0] * allKeysSize + j * keySize];
//                        for (int l = 1; l < keySize; l++) {
//                            intVal[2] = intVal[2] << 8;
//                            intVal[2] = intVal[2] | computeKeys[gate.inputIndices[0] * allKeysSize + j * keySize + l];
//                        }
                        intVal[3] = 0 | m;
                        intVal += 4;
                    }
                }

                //compute aes on the input
                EVP_EncryptUpdate(aes, splitOutput, intVal, splitInput, numParties*NUM_BYTES*splitCounterSize*2);

                //xor with other outputs
                for (int j = 0; j < numParties; j++) {

                    temp = &splitOutput[2*j * NUM_BYTES * splitCounterSize];
                    temp2 = &splitOutput[2*j * NUM_BYTES * splitCounterSize + NUM_BYTES* splitCounterSize];
                    for (int m = 0; m < allKeysSize; m++) {
                        splitKey[m] ^= temp[m];
                        splitKey[m + allKeysSize] ^= temp2[m];
                    }
//                    for (int m = 0; m < allKeysSize; m++) {
//                        splitKey[m] ^= splitOutput[2*j * NUM_BYTES * splitCounterSize + m];
//                        splitKey[m + allKeysSize] ^= splitOutput[2*j * NUM_BYTES * splitCounterSize + NUM_BYTES* splitCounterSize + m];
//                    }

                }
            }

            for (int j=0; j<allKeysSize; j++) {
                computeKeys[gate.outputIndex1*allKeysSize + j] = splitKey[j];
                computeKeys[gate.outputIndex2*allKeysSize + j] = splitKey[j + allKeysSize];
            }

            splitIndex++;


        } else if (gate.gateType == 1) {//AND gate
            entry = andIndex * 4 * (allKeysSize + 1) + (2 * publicValues[gate.inputIndices[0]] + publicValues[gate.inputIndices[1]]) * outputSize;

            //copy g̃Λw
            memcpy(andKey, garbleTableAnd + entry, outputSize);

            if (isLookup) {
                for (int j = 0; j < numParties; j++) {
                    index = j;
                    index = index << 1;
                    index = index | publicValues[gate.inputIndices[1]];
                    index = index << 7;
                    temp = &computeKeys[gate.inputIndices[0] * allKeysSize + j * keySize];
                    index = index | *temp;
                    temp++;
                    for (int l = 1; l < keySize; l++, temp++) {
                        index = index << 8;
                        index = index | *temp;
                    }
//                    index = index | computeKeys[gate.inputIndices[0] * allKeysSize + j * keySize];
//                    for (int l = 1; l < keySize; l++) {
//                        index = index << 8;
//                        index = index | computeKeys[gate.inputIndices[0] * allKeysSize + j * keySize + l];
//                    }

                    //xor the first lookup value to the garbled table
                    for (int l = 0; l < outputSize; l++) {
                        andKey[l] ^= lookupTableAnd[index * outputSize + l];
                    }

                    index = j;
                    index = index << 1;
                    index = index | publicValues[gate.inputIndices[0]];
                    index = index << 7;
                    temp = &computeKeys[gate.inputIndices[1] * allKeysSize + j * keySize];
                    index = index | *temp;
                    temp++;
                    for (int l = 1; l < keySize; l++, temp++) {
                        index = index << 8;
                        index = index | *temp;
                    }
//                    index = index | computeKeys[gate.inputIndices[1] * allKeysSize + j * keySize];
//                    for (int l = 1; l < keySize; l++) {
//                        index = index << 8;
//                        index = index | computeKeys[gate.inputIndices[1] * allKeysSize + j * keySize + l];
//                    }
                    //xor the first lookup value to the garbled table
                    for (int l = 0; l < outputSize; l++) {
                        andKey[l] ^= lookupTableAnd[index * outputSize + l];
                    }
                }
            } else {


                for (int j = 0; j < numParties; j++) {

                    intVal = (int *) &input[j * NUM_BYTES * counterSize];
                    byteVal = &input[j * NUM_BYTES * counterSize];
                    //Prepare the input for the aes function.
                    for (int m = 0; m < counterSize; m++) {
                        //prepre the first aes input - i, b, k u,a, counter
                        intVal[0] = j;

                        byteVal[4] = publicValues[gate.inputIndices[0]];
                        byteVal[5] = publicValues[gate.inputIndices[1]];
                        temp0 = &computeKeys[gate.inputIndices[0] * allKeysSize + j * keySize];
                        temp1 = &computeKeys[gate.inputIndices[1] * allKeysSize + j * keySize];
//                        intVal[2] = 0 | *temp;
//                        temp++;
                        for (int l = 0; l < keySize; l++, temp0++, temp1++) {
//                            intVal[2] = intVal[2] << 8;
                            byteVal[6 + l] = *temp0;
                            byteVal[6 + l + keySize] = *temp1;

//                            byteVal[6 + l] = 0;
//                            byteVal[6 + l + keySize] = 0;
                        }
//                        intVal[2] = 0 | computeKeys[gate.inputIndices[0] * allKeysSize + j * keySize];
//                        for (int l = 1; l < keySize; l++) {
//                            intVal[2] = intVal[2] << 8;
//                            intVal[2] = intVal[2] | computeKeys[gate.inputIndices[0] * allKeysSize + j * keySize + l];
//                        }

                        byteVal[6+2*keySize] = m;

                        for (int l= 7 + 2*keySize; l<16; l++){
                            byteVal[l] = 0;
                        }

                        intVal+=4;
                        byteVal+=16;
                    }

//                    for (int m = 0; m < counterSize; m++) {
//                        //prepre the second aes input - i, b, k u,a, counter
//                        intVal[0] = j;
//                        intVal[1] = publicValues[gate.inputIndices[0]];
//                        temp = &computeKeys[gate.inputIndices[1] * allKeysSize + j * keySize];
//                        intVal[2] = 0 | *temp;
//                        temp++;
//                        for (int l = 1; l < keySize; l++, temp++) {
//                            intVal[2] = intVal[2] << 8;
//                            intVal[2] = intVal[2] | *temp;
//                        }
////                        intVal[2] = 0 | computeKeys[gate.inputIndices[1] * allKeysSize + j * keySize];
////                        for (int l = 1; l < keySize; l++) {
////                            intVal[2] = intVal[2] << 8;
////                            intVal[2] = intVal[2] | computeKeys[gate.inputIndices[1] * allKeysSize + j * keySize +l];
////                        }
//
//                        intVal[3] = 0 | m;
//                        intVal+=4;
//                    }
                }

                //compute aes on the input
                EVP_EncryptUpdate(aes, output, intVal, input, numParties*NUM_BYTES*counterSize);

                //xor with other outputs
                for (int j = 0; j < numParties; j++) {

                    for (int m = 0; m < outputSize; m++) {
                        andKey[m] ^= output[j * NUM_BYTES * counterSize + m];
//                        andKey[m] ^= output[2*j * NUM_BYTES * counterSize + NUM_BYTES* counterSize + m];
                    }
                }
            }

            publicValues[gate.outputIndex1] = andKey[0];
            for (int j=0; j<allKeysSize; j++) {
                computeKeys[gate.outputIndex1*allKeysSize + j] = andKey[j+1];
            }

            andIndex++;

        } else if (gate.gateType == 12) { //NOT gate
            publicValues[gate.outputIndex1] = publicValues[gate.inputIndices[0]] ^ 1;

            for (int j=0; j<allKeysSize; j++){
                computeKeys[gate.outputIndex1*allKeysSize + j] = computeKeys[gate.inputIndices[0]*allKeysSize + j];
            }
        } else if (gate.gateType == 6){ //XOR gate
            //If g is a XOR gate, then each party computes the public value on the output wire w to be γ =α ⊕ β.
            // In addition, for every j = 1, . . . , n it computes kjw,γ = kju,α ⊕ kjv,β
            publicValues[gate.outputIndex1] = publicValues[gate.inputIndices[0]];
            for (int j=1; j<gate.inFan; j++){
                publicValues[gate.outputIndex1] = publicValues[gate.outputIndex1] ^ publicValues[gate.inputIndices[j]];
            }

            for (int j=0; j<allKeysSize; j++){
                computeKeys[gate.outputIndex1*allKeysSize + j] = computeKeys[gate.inputIndices[0]*allKeysSize + j];
                for (int k=1; k<gate.inFan; k++){
                    computeKeys[gate.outputIndex1*allKeysSize + j] ^= computeKeys[gate.inputIndices[k]*allKeysSize + j];
                }
            }
        }
    }

    delete [] splitKey;
    delete [] andKey;
    delete [] input;
    delete [] output;
    delete [] splitInput;
    delete [] splitOutput;
}

vector<byte> Party::computeOutput(const vector<byte> & computeKeys, byte* publicValues) {

    vector<byte> outputs(circuit.getNrOfOutput());
    vector<int> outputIndices;
    int index = 0;

    //compute the xor of the public value and the lambda for each output wire.
    for (int i = 0; i < numParties; i++) {

        outputIndices = circuit.getPartyOutputs(i);
        for (int j = 0; j < outputIndices.size(); j++) {
            outputs[index] = publicValues[outputIndices[j]] ^ outputLambdas[index];
            index++;
        }
    }
    return outputs;
}