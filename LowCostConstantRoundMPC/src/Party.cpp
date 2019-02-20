#include "../include/Party.hpp"

Party::Party(int argc, char* argv[])
    : MPCProtocol("LowCostConstantRoundMPC", argc, argv)
    {

    id = stoi(this->getParser().getValueByKey(arguments, "partyID"));
    circuit.readCircuit(this->getParser().getValueByKey(arguments, "circuitFile").c_str());
    numThreads = stoi(this->getParser().getValueByKey(arguments, "numThreads"));
    times = stoi(this->getParser().getValueByKey(arguments, "internalIterationsNumber"));

    vector<string> subTaskNames{"Preprocess", "Bits generation", "Triples Generation", "Generate masks and keys",
                                "Secure product computation", "Offline",
                                "Garbled circuit generation", "Reveal outputs", "Reveal inputs", "Open garble", "Online"};
    this->timer->addTaskNames(subTaskNames);
    //Print performance of each function to an output file
    string outputName = "Output" +this->getParser().getValueByKey(arguments, "partyID")
            + "_" + this->getParser().getValueByKey(arguments, "circuitFile") + "_Threads="
            +this->getParser().getValueByKey(arguments, "numThreads") +
                        "_BucketSize="+this->getParser().getValueByKey(arguments, "B")
                        +".csv";
    outputFile.open (outputName);
    outputFile << "Performance:"<<endl;
    outputFile << "Bits generation, Triples generation, Generate masks and keys, Secure product computation, Garbled circuit generation, Reveal outputs, Reveal inputs, Open garble, Total offline phase, Online phase"<<endl;

    numParties = parties.size() + 1;
    auto key = prg.generateKey(128);
    prg.setKey(key);

    utils.setParameters(id, parties, &prg, numThreads, &outputFile);

    aes = EVP_CIPHER_CTX_new();
    cipher = EVP_aes_256_ecb();

    auto fixedKey = utils.coinTossing(1, 256)[0];
    EVP_EncryptInit(aes, cipher, fixedKey.data(), NULL);

    tinyOT.init(id, &prg, parties, &utils, numThreads, aes, &outputFile,
                stoi(this->getParser().getValueByKey(arguments, "B")));

    //read the inputs from a file
    inputs = readInputs(this->getParser().getValueByKey(arguments, "inputsFile"));
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
    //delete the allocated memory.
    _mm_free(allWiresKeys);
    _mm_free(gatesEntries);
    _mm_free(xorMemory);

    for (int i=0; i<parties.size(); i++){
        delete parties[i];
    }

    for (int i=0; i<sharings.size(); i++){
        delete sharings[i];
    }

    for (int i=0; i<xorSharings.size(); i++){
        delete xorSharings[i];
    }

    EVP_CIPHER_CTX_cleanup(aes);
    EVP_CIPHER_CTX_free(aes);

    io_service.stop();
    ios_ot.stop();

    outputFile.close();
    delete timer;
}

void Party::run() {

    chrono::high_resolution_clock::time_point start, end;
    int allOnlineTime = 0;

    for (iteration =0; iteration<times; iteration++) {
        //offline phase
        initTimes();
        start = chrono::high_resolution_clock::now();
        timer->startSubTask("Offline", iteration);
        runOffline();
        timer->endSubTask("Offline", iteration);
        end = chrono::high_resolution_clock::now();
        auto offlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        outputFile << offlineTime << ",";

        initTimes();

        //online phase
        start = chrono::high_resolution_clock::now();
        timer->startSubTask("Online", iteration);
        runOnline();
        timer->endSubTask("Online", iteration);
        end = chrono::high_resolution_clock::now();
        auto onlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        allOnlineTime += onlineTime;
        outputFile << onlineTime << endl;
    }

    cout<<"online took "<< allOnlineTime/times<<endl;
}


void Party::runOffline() {
    preprocess();
}

void Party::runOnline() {
    compute();
}

void Party::openGarble(){
    int tablesSize = circuit.getNrOfAndGates()*4*numParties;
    block* myTable = (block *) _mm_malloc(tablesSize*NUM_BYTES, 32);
    block* otherTable = (block *) _mm_malloc((numParties-1)*tablesSize*NUM_BYTES, 32);

    memcpy((byte*)myTable, (byte*)gatesEntries, tablesSize*NUM_BYTES);

    utils.roundFunctionSameInput(myTable, otherTable, tablesSize*NUM_BYTES);
    for (int j=0; j<numParties - 1; j++){

        for (int i=0; i<tablesSize; i++){
            gatesEntries[i] = _mm_xor_si128(gatesEntries[i], otherTable[j*tablesSize + i]);
        }
    }

    _mm_free(myTable);
    _mm_free(otherTable);
}

void Party::preprocess(){
    //Call bits and ands of tiny OT, in order to generate sharings and multiplication triples to use later in the protocol.
    int numShares = circuit.getNrOfInput() + circuit.getNrOfAndGates();
    auto start = chrono::high_resolution_clock::now();
    timer->startSubTask("Preprocess", iteration);
    sharings = tinyOT.bits(numShares);
    timer->endSubTask("Preprocess", iteration);
    auto end = chrono::high_resolution_clock::now();
    auto time = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    outputFile << time<< ",";

    R = tinyOT.getR();

    start = chrono::high_resolution_clock::now();
    timer->startSubTask("Triples Generation", iteration);
    tinyOT.ands(circuit.getNrOfAndGates());
    timer->endSubTask("Triples Generation", iteration);
    end = chrono::high_resolution_clock::now();
    time = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    outputFile << time<< ",";


    int numWires = circuit.getNrOfInput() + circuit.getNrOfGates();
    allWiresSharings.resize(numWires); //Will hols all wire's sharings
    allWiresKeys = (block *) _mm_malloc(numWires*NUM_BYTES, 32);    //Will hold all wire's zero keys

    start = chrono::high_resolution_clock::now();
    timer->startSubTask("Generate masks and keys", iteration);
    //2. Generate wire masks and keys: Passing through the wires of the circuit topologically, proceed as follows:
    //  • If w is a circuit-input wire, or the output of an AND gate:
    //      (a) Generate a random wire mask [λw] using the Bits command of Π n-TinyOT.
    //      (b) Every Pi samples a key kw,0← {0, 1}^κ and sets kw,1= kw,0 ⊕ R
    //  • If the wire w is the output of a XOR gate:
    //      (a) The parties compute the mask on the output wire as [λw] = [λu] + [λv].
    //      (b) Every Pi sets kw,0= ku,0 ⊕ k v,0 and kw,1= kw,0 ⊕ R.
    generateMasksAndKeys(&tinyOT, sharings, allWiresSharings);
    timer->endSubTask("Generate masks and keys", iteration);

   end = chrono::high_resolution_clock::now();
    time = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    outputFile << time<< ",";

    start = chrono::high_resolution_clock::now();
    timer->startSubTask("Secure product computation", iteration);
    //3. Secure product computations:
    //  (a) For each AND gate g ∈ G, the parties compute λuv= λu · λv by calling Multiply on Fn-TinyOT.
    //  (b) For each AND gate g, party Pi can compute an additive share of the 3n values:
    //          λu · Rj, λv · Rj, λuvw · Rj, for j ∈ [n] where λuvw := λuv + λw.
    //      Each Pi then uses these to compute, for a, b ∈ {0,1}^2 a share of:
    //          ρ j,a,b = λ u · R j ⊕ a · λ v · R j ⊕ b · λ uvw · R j ⊕ a · b · R j
    secureProductComputation(&tinyOT, allWiresSharings);
    timer->endSubTask("Secure product computation", iteration);
    end = chrono::high_resolution_clock::now();
    time = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    outputFile << time<< ",";
//
    start = chrono::high_resolution_clock::now();
    timer->startSubTask("Garbled circuit generation", iteration);
    //4. Garble gates: For each AND gate g ∈ G, each j ∈ [n], and the four combinations of a, b ∈ {0, 1}^2,
    //the parties compute shares of the j-th entry of the garbled gate g̃ a,b as follows:
    //  • P j sets (gj,a,b) = ρj,a,b ⊕ Fku,a,kv,b(g||j) ⊕ kw,0
    //  • For every i != j, Pi sets (g̃ a,b)i  = ρj,a,b ⊕ F ku,akv,b(g||j)
    garble();
    timer->endSubTask("Garbled circuit generation", iteration);
    end = chrono::high_resolution_clock::now();
    time = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    outputFile << time<< ",";

    start = chrono::high_resolution_clock::now();
    timer->startSubTask("Reveal outputs", iteration);
    //5. Reveal masks for output wires: For every circuit-output-wire w, the parties run Π Open to reveal λw to all the parties.
    revealOutputs(&tinyOT, allWiresSharings);
    timer->endSubTask("Reveal outputs", iteration);
    end = chrono::high_resolution_clock::now();
    time = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    outputFile << time<< ",";

    start = chrono::high_resolution_clock::now();
    timer->startSubTask("Reveal inputs", iteration);
    //6. Privately open masks for input wires: For every circuit input wire w corresponding to party Pi’s input, the parties run ΠiOpen to open λw to Pi.
    revealInputs(&tinyOT, allWiresSharings);
    timer->endSubTask("Reveal inputs", iteration);
    end = chrono::high_resolution_clock::now();
    time = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    outputFile << time<< ",";

    start = chrono::high_resolution_clock::now();
    timer->startSubTask("Open garble", iteration);
    openGarble();
    timer->endSubTask("Open garble", iteration);
    end = chrono::high_resolution_clock::now();
    time = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    outputFile << time<< ",";
}

void Party::revealInputs(TinyOT* tinyOT, vector<Sharing*> & allWiresSharings){
    vector<Sharing*> inputSharings;

    vector<byte> lambdaInputs;
    vector<int> inputIndices;

    //open the sharings of all input wires for each party.
    //save the sharings of this party's in put wires as allLambdaInputs.
    for (int i=0; i<numParties; i++){

        inputIndices = circuit.getPartyInputs(i);
        inputSharings.resize(inputIndices.size());

        for (int j=0; j<inputIndices.size(); j++){

            inputSharings[j] = allWiresSharings[inputIndices[j]];
        }

        lambdaInputs = tinyOT->openToParty(i, inputSharings);
        if (i == id){
            allLambdaInputs = lambdaInputs;
        }
    }
}

void Party::revealOutputs(TinyOT* tinyOT, vector<Sharing*> & allWiresSharings){

    vector<Sharing*> outputSharings(circuit.getNrOfOutput());

    vector<int> outputIndices;
    int index = 0;

    //get all the output wires' sharings
    for (int i=0; i<numParties; i++){

        outputIndices = circuit.getPartyOutputs(i);
        for (int j=0; j<outputIndices.size(); j++){

            outputSharings[index] = allWiresSharings[outputIndices[j]];
            index++;
        }
    }

    //open the sharings and set the revealed output values at allLambdaOutputs.
    allLambdaOutputs = tinyOT->open(outputSharings);
}

void Party::garble(){

    auto gates = circuit.getGates();
    int gatesSize = gates.size();
    Gate gate;
    int andIndex = 0;


    /**
     * For each AND gate g ∈ G, each j ∈ [n], and the four combinations of a, b ∈ {0, 1} 2, the parties compute shares
     * of the j-th entry of the garbled gate g̃ a,b as follows:
     * • P j sets (g̃ a,b)^j = ρa,b^j ⊕ F ku,a,kv,b (g||j) ⊕ k w,0.
     * • For every i != j, Pi sets j(g̃ a,b) = ρ a,b^i ⊕ F k u,a,kv,b(g||j)
     */

    //Instead of computing F ku,a,kv,b (g||j), which requires many expansive set key operations, we compute
    //AES(K) XOR K, where K = 2k1 XOR 4k2 XOR x. k1,k2 are the two keys, x is the input (i.e. g || j), and AES uses a
    // fixed, random key. This way the computation is much faster.
    block key, twoA, fourB;
    block key0, key1, outputKey;
    block* input = (block *) _mm_malloc(numParties*NUM_BYTES, 32);
    block* output = (block *) _mm_malloc(numParties*NUM_BYTES, 32);
    int size, index;

    for (int i=0; i<gatesSize; i++) {
        gate = gates[i];
        if (gate.gateType == 1) {//AND gate

            for (int k = 0; k < 4; k++) {
                //Get the two input keys.
                if (k == 0) {
                    key0 = allWiresKeys[gate.inputIndex1];
                    key1 = allWiresKeys[gate.inputIndex2];

                } else if (k == 1) {
                    key0 = allWiresKeys[gate.inputIndex1];
                    key1 = _mm_xor_si128(allWiresKeys[gate.inputIndex2], R);
                } else if (k == 2) {
                    key0 = _mm_xor_si128(allWiresKeys[gate.inputIndex1], R);
                    key1 = allWiresKeys[gate.inputIndex2];
                } else if (k == 3) {
                    key0 = _mm_xor_si128(allWiresKeys[gate.inputIndex1], R);
                    key1 = _mm_xor_si128(allWiresKeys[gate.inputIndex2], R);

                }

                outputKey = allWiresKeys[gate.outputIndex];

                //Shift left to double A for security (actually the 2 64 bit are shifted and not the whole 128 bit block
                twoA = _mm_slli_epi64(key0,1);
                //Shift right instead of shifting left twice.This is secure since the alignment is broken
                fourB = _mm_srli_epi64(key1,1);
                key = _mm_xor_si128(twoA, fourB);
                //prepare the input for the aes function
                for (int j = 0; j < numParties; j++) {
                    input[j] = _mm_xor_si128(key, _mm_set_epi64x(i, j));
                }

                //compute the aes on the input. we compute all aes operations for the same keys at once.
                EVP_EncryptUpdate(aes, (byte *) output, &size, (byte *) input, numParties * NUM_BYTES);

                //get the output of all input blocks
                for (int j = 0; j < numParties; j++) {
                    output[j] = _mm_xor_si128(output[j], input[j]);
                }

                //calculate ρa,b^j ⊕ F ku,a,kv,b (g||j) ⊕ k w,0.
                for (int j = 0; j < numParties; j++) {
                    index = andIndex * 4 * numParties + k * numParties + j;
                    gatesEntries[index] = _mm_xor_si128(gatesEntries[index], output[j]);

                    if (id == j) {
                        gatesEntries[index] = _mm_xor_si128(gatesEntries[index], outputKey);
                    }
                }
            }

            andIndex++;
        }
    }

    _mm_free(input);
    _mm_free(output);
}

void Party::secureProductComputation(TinyOT* tinyOT, vector<Sharing*> & allWiresSharings){
    auto gates = circuit.getGates();
    int gatesSize = gates.size();
    Gate gate;
    int andIndex = 0;

    //These vectors are the input for the multiply function.
    vector<Sharing*> u(circuit.getNrOfAndGates()), v(circuit.getNrOfAndGates());

    //  (a) For each AND gate g ∈ G, the parties compute λuv= λu · λv by calling Multiply on Fn-TinyOT.
    for (int i=0; i<gatesSize; i++) {
        gate = gates[i];
        if (gate.gateType == 1) {//AND gate

            //put the sharings of the input wires in the multiply vectors.
            u[andIndex] = allWiresSharings[gate.inputIndex1];
            v[andIndex] = allWiresSharings[gate.inputIndex2];
            andIndex++;
        }
    }

    block* memory = (block*) _mm_malloc(circuit.getNrOfAndGates()*2*(numParties - 1)*NUM_BYTES, 32);
    auto multiplications = tinyOT->allocateSharingsMemory(circuit.getNrOfAndGates(), numParties - 1, memory);

    //call the multiply function of tiny OT.
    tinyOT->multiply(u, v, multiplications);

    andIndex = 0;

    //  (b) For each AND gate g, party Pi can compute an additive share of the 3n values:
    //          λu · Rj, λv · Rj, λuvw · Rj, for j ∈ [n] where λuvw := λuv + λw.
    //      Each Pi then uses these to compute, for a, b ∈ {0,1}^2 a share of:
    //          ρ j,a,b = λ u · R j ⊕ a · λ v · R j ⊕ b · λ uvw · R j ⊕ a · b · R j
    block uShare, vShare, uvwShare;
    gatesEntries = (block *) _mm_malloc(circuit.getNrOfAndGates()*4*numParties*NUM_BYTES, 32);

    block* tempMemory = (block*) _mm_malloc(NUM_BYTES*2*(numParties-1), 32);
    auto uvwLambda = tinyOT->allocateSharingsMemory(1, numParties - 1, tempMemory)[0];
    Sharing *uLambda, *vLambda;
    for (int i=0; i<gatesSize; i++) {
        gate = gates[i];
        if (gate.gateType == 1) {//AND gate
            uLambda = u[andIndex];
            vLambda = v[andIndex];
            *uvwLambda = *multiplications[andIndex];
            *uvwLambda += *allWiresSharings[gate.outputIndex];
            for (int j=0; j<numParties; j++){
                // compute an additive share of the values λu · Rj, λv · Rj, λuvw · Rj
                if (j == id){

                    if (uLambda->getX() == 1) {

                        uShare = R;
                    } else {
                        uShare = _mm_setzero_si128();
                    }
                    if (vLambda->getX() == 1) {
                        vShare = R;
                    } else {
                        vShare = _mm_setzero_si128();
                    }
                    if (uvwLambda->getX() == 1) {
                        uvwShare = R;
                    } else {
                        uvwShare = _mm_setzero_si128();
                    }
                    for (int k=0; k<numParties - 1; k++){
                        uShare = _mm_xor_si128(uShare, uLambda->getKey(k));
                        vShare = _mm_xor_si128(vShare, vLambda->getKey(k));
                        uvwShare = _mm_xor_si128(uvwShare, uvwLambda->getKey(k));
                    }
                } else {
                    if (j<id){
                        uShare = uLambda->getMac(j);
                        vShare = vLambda->getMac(j);
                        uvwShare = uvwLambda->getMac(j);
                    } else {
                        uShare = uLambda->getMac(j - 1);
                        vShare = vLambda->getMac(j - 1);
                        uvwShare = uvwLambda->getMac(j - 1);
                    }

                }
                //compute, for a, b ∈ {0,1}^2 a share of:
                // ρ j,a,b = λu · Rj ⊕ a · λv · Rj ⊕ b · λuvw · Rj ⊕ a · b · Rj
                //case a = b = 0:  ρ j,a,b = λu · Rj
                gatesEntries[andIndex*4*numParties + j] = uvwShare;
                //case a = 0, b = 1:  ρ j,a,b = λu · Rj ⊕ b · λuvw · Rj
                gatesEntries[andIndex*4*numParties + numParties + j] = _mm_xor_si128(uShare, uvwShare);
                //case a = 1, b = 0:  ρ j,a,b = λu · Rj ⊕ a · λv · Rj
                gatesEntries[andIndex*4*numParties + 2*numParties + j] = _mm_xor_si128(uvwShare, vShare);
                //case a = b = 1:  ρ j,a,b = λu · Rj ⊕ a · λv · Rj ⊕ b · λuvw · Rj ⊕ a · b · Rj
                gatesEntries[andIndex*4*numParties + 3*numParties + j] = _mm_xor_si128(gatesEntries[andIndex*4*numParties + 2*numParties + j], uShare);
                if (id == j) {
                    gatesEntries[andIndex * 4 * numParties + 3*numParties + j] = _mm_xor_si128(gatesEntries[andIndex * 4 * numParties + 3*numParties + j], R);
                }


            }

            andIndex++;
        }
    }

    _mm_free(memory);
    for (int i=0; i<multiplications.size(); i++){
        delete multiplications[i];
    }

    _mm_free(tempMemory);
    delete uvwLambda;
}

void Party::generateMasksAndKeys(TinyOT* tinyOT, vector<Sharing*> & sharings, vector<Sharing*> & allWiresSharings){
    //2. Generate wire masks and keys: Passing through the wires of the circuit topologically, proceed as follows:
    //  • If w is a circuit-input wire, or the output of an AND gate:
    //      (a) Generate a random wire mask [λw] using the Bits command of Π n-TinyOT.
    int numShares = circuit.getNrOfInput() + circuit.getNrOfAndGates();

    //      (b) Every Pi samples a key kw,0← {0, 1}^κ and sets kw,1= kw,0 ⊕ R
    //We will sample all keys at once
    vector<byte> zeroKeys(NUM_BYTES * numShares);
    prg.getPRGBytes(zeroKeys, 0, NUM_BYTES * numShares);


    int partyInputSize;
    int sharingIndex = 0;
    int wireIndex;

    xorMemory = (block*) _mm_malloc(circuit.getNrOfXorGates()*(numParties - 1)*2*NUM_BYTES, 32);
    xorSharings = tinyOT->allocateSharingsMemory(circuit.getNrOfXorGates(), numParties - 1, xorMemory);

    //For each input wire, set the calculated sharing and keys
    for (int i=0; i<circuit.getNrOfParties(); i++){
        auto partyInputs = circuit.getPartyInputs(i);
        partyInputSize = partyInputs.size();
        for (int j=0; j<partyInputSize; j++){
            wireIndex = partyInputs[j];

            //set the sharing
            allWiresSharings[wireIndex] = sharings[sharingIndex];

            //set zero key
            memcpy((byte*)&allWiresKeys[wireIndex], zeroKeys.data() + sharingIndex*NUM_BYTES, NUM_BYTES);
            sharingIndex++;

        }
    }
    auto gates = circuit.getGates();
    int gatesSize = gates.size();
    Gate gate;
    int xorIndex = 0;

    for (int i=0; i<gatesSize; i++){
        gate = gates[i];
        wireIndex = gate.outputIndex;
        //For each AND gate output wire, set the calculated sharing and keys
        if (gate.gateType == 1) {//AND gate
            //set the sharing
            allWiresSharings[wireIndex] = sharings[sharingIndex];

            //set zero key
            memcpy((byte*)&allWiresKeys[wireIndex], zeroKeys.data() + sharingIndex*NUM_BYTES, NUM_BYTES);
            sharingIndex++;
        }else if (gate.gateType == 12) { //NOT gate
            allWiresSharings[wireIndex] = allWiresSharings[gate.inputIndex1];
            allWiresKeys[wireIndex] = _mm_xor_si128(allWiresKeys[gate.inputIndex1], R);

        } else if (gate.gateType == 6) { //XOR gate
            *xorSharings[xorIndex] = *allWiresSharings[gate.inputIndex1];
            *xorSharings[xorIndex] += *allWiresSharings[gate.inputIndex2];
            allWiresSharings[wireIndex] = xorSharings[xorIndex++];

            allWiresKeys[wireIndex] = _mm_xor_si128(allWiresKeys[gate.inputIndex1], allWiresKeys[gate.inputIndex2]);

        }
    }
}

bitVector Party::readInputs(string inputFileName) {
    //Read the input from the given input file
    ifstream myfile;
    int inputSize = circuit.getPartyInputs(id).size();
    bitVector inputs(inputSize);
    int inputBit;
    myfile.open(inputFileName);

    for (int i = 0; i < inputSize; i++) {
        myfile >> inputBit;
        inputs[i] = inputBit;
    }
    myfile.close();
    return inputs;
}

bitVector Party::compute(){

    int allWiresSize = circuit.getNrOfInput() + circuit.getNrOfGates();

    //This array will hold the actual keys values of all the wires.
    block* computeKeys = (block *) _mm_malloc(numParties*allWiresSize*NUM_BYTES, 32);
    bitVector publicValues(allWiresSize);

    //get the input keys
    sendGarblesLabels(inputs, computeKeys, publicValues);

    //compute the circuit locally.
    localComputeCircuit(computeKeys, publicValues);

    //get the real output
    outputs = computeOutput(computeKeys, publicValues);

    _mm_free(computeKeys);

    return outputs;

}

bitVector Party::computeOutput(block* computeKeys, const bitVector & publicValues){

    bitVector outputs(circuit.getNrOfOutput());
    vector<int> outputIndices;
    int index = 0;

    //compute the xor of the public value and the lambda for each output wire.
    for (int i=0; i<numParties; i++){

        outputIndices = circuit.getPartyOutputs(i);
        for (int j=0; j<outputIndices.size(); j++){
            outputs[index] = publicValues[outputIndices[j]] ^ allLambdaOutputs[index];
            index++;
        }
    }
//    cout<<"my output:"<<endl;
//    cout<<outputs<<endl;

    return outputs;
}

void Party::localComputeCircuit(block* computeKeys, const bitVector & publicValues){

    vector<Gate> gates = circuit.getGates();
    Gate gate;
    int gatesSize = gates.size();

    block *u, *v, *w;
    int entry;
    block input, output;
    int size, andIndex = 0;
    block offlineKey1;
    block twoA, fourB, key;

    /* Passing through the circuit topologically, the parties can now locally compute the following operations for
    * each gate g. Let the gates input wires be labelled u and v, and the output wire be labelled w. Let a and b be
    * the respective public values on the input wires.
    * 1. If g is a XOR gate, set the public value on the output wire to be c = a + b.
    *    In addition, for every j ∈ [n], each party computes k w,c = k u,a ⊕ k v,b.
    * 2. If g is an AND gate , then each party computes, for all j ∈ [n]:
    *    kw,c = g̃ a,b ⊕ (⊕i = 1,... , n F ku,a kv,b(g||j))
    */
    for (int i=0; i<gatesSize; i++){
        gate = gates[i];

        u = computeKeys + gate.inputIndex1*numParties;
        v = computeKeys + gate.inputIndex2*numParties;
        w = computeKeys + gate.outputIndex*numParties;

        if (gate.gateType == 1) {//AND gate

            entry = 2*publicValues[gate.inputIndex1] + publicValues[gate.inputIndex2];
            for (int j=0; j<numParties; j++){

                //get the garbled value for this party in the current gate and entry
                w[j] = gatesEntries[andIndex*numParties*4 + entry*numParties + j];

                for (int k=0; k<numParties; k++) {

                    //instead of computing F ku,a kv,b(g||j) we compute AES(K) XOR K, where K = 2k1 XOR 4k2 XOR g||j

                    //Shift left to double A for security (actually the 2 64 bit are shifted and not the whole 128 bit block
                    twoA = _mm_slli_epi64(u[k],1);
                    //Shift right instead of shifting left twice.This is secure since the alignment is broken
                    fourB = _mm_srli_epi64(v[k],1);
                    key = _mm_xor_si128(twoA, fourB);
                    input = _mm_xor_si128(key, _mm_set_epi64x(i, j));

                    //compute aes on the input
                    EVP_EncryptUpdate(aes, (byte *) &output, &size, (byte *) &input, NUM_BYTES);

                    output = _mm_xor_si128(output, input);

                    w[j] = _mm_xor_si128(w[j], output);
                }
            }

            //Given k1w,γ, . . . , knw,γ, each party Pi compares the ith value to the garbled labels kiw,0, kiw,1
            // that it input in the offline phase on this wire.
            // If it equals kiw,0 then it sets the public value on wire w to be γ = 0;
            // If it equals kiw,1 then it sets the public value on wire w to be γ = 1;
            // otherwise abort.

            long *ap = (long*) &w[id];
            long *bp = (long*) &allWiresKeys[gate.outputIndex];
            if ((ap[0] == bp[0]) && (ap[1] == bp[1])){

                //it equals to kiw,0 - set the public value on wire w to be γ = 0
                publicValues[gate.outputIndex] = 0;
            } else {
                offlineKey1 = _mm_xor_si128(allWiresKeys[gate.outputIndex], R);

                bp = (long*) &offlineKey1;
                if ((ap[0] == bp[0]) && (ap[1] == bp[1])){
                    //it equals to kiw,1 - set the public value on wire w to be γ = 1
                    publicValues[gate.outputIndex] = 1;
                } else {
                    //the output key is not equal to any of the precomputed keys - abort
                    outputFile<<"CHEATING!!!"<<endl;
                    throw CheatAttemptException("cheating in compute");
                }
            }

            andIndex++;

        } else if (gate.gateType == 12) { //NOT gate
            publicValues[gate.outputIndex] = publicValues[gate.inputIndex1] ^ 1;

            for (int j=0; j<numParties; j++){
                w[j] = u[j];
            }
        } else if (gate.gateType == 6){ //XOR gate
            //If g is a XOR gate, then each party computes the public value on the output wire w to be γ =α ⊕ β.
            // In addition, for every j = 1, . . . , n it computes kjw,γ = kju,α ⊕ kjv,β
            publicValues[gate.outputIndex] = publicValues[gate.inputIndex1] ^ publicValues[gate.inputIndex2];

            for (int j=0; j<numParties; j++){
                w[j] = _mm_xor_si128(u[j], v[j]);
            }
        }

    }
}

void Party::sendGarblesLabels(const bitVector & inputs, block* computeKeys, const bitVector & publicValues){
    int myInputsSize = inputs.size();
    vector<bitVector> inputsBits(numParties);
    auto myInputsIndices = circuit.getPartyInputs(id);

    //Compute α = x ⊕ λ for each input wire of this party
    inputsBits[id].resize(myInputsSize);
    for (int i=0; i<myInputsSize; i++){
        inputsBits[id][i] = inputs[i] ^ allLambdaInputs[i];
        publicValues[myInputsIndices[i]] = inputsBits[id][i];
    }

    //Braodcast all input bits of all parties
    for (int i=0; i<numParties; i++){
        if (id == i){
            utils.broadcast(i, inputsBits[id].data(), inputsBits[id].sizeBytes());
        } else {
            inputsBits[i].resize(circuit.getPartyInputs(i).size());
            utils.broadcast(i, inputsBits[i].data(), inputsBits[i].sizeBytes());
        }
    }

    int inputSize = circuit.getNrOfInput();
    block* myInputKeys = (block *) _mm_malloc(inputSize*NUM_BYTES, 32);
    bitVector currentInputs;
    int inputIndex = 0;

    //for each input wire, get the key corresponding to the input bit
    for (int i=0; i<numParties; i++){
        auto wireIndices = circuit.getPartyInputs(i);
        currentInputs = inputsBits[i];
        for (int j=0; j<wireIndices.size(); j++){
            publicValues[wireIndices[j]] = currentInputs[j];
            if (currentInputs[j] == 0) {
                myInputKeys[inputIndex] = allWiresKeys[wireIndices[j]];
            } else {
                myInputKeys[inputIndex] = _mm_xor_si128(allWiresKeys[wireIndices[j]], R);
            }

            computeKeys[wireIndices[j]*numParties + id] = myInputKeys[inputIndex];
            inputIndex++;
        }
    }

    block* otherInputKeys = (block *) _mm_malloc(inputSize*NUM_BYTES, 32);

    //broadcast all the input keys
    for (int i=0; i<numParties; i++){

        if (id == i){
            utils.broadcast(i, (byte*)myInputKeys, inputSize*NUM_BYTES);
        } else {

            utils.broadcast(i, (byte*)otherInputKeys, inputSize*NUM_BYTES);

            inputIndex = 0;
            for (int j=0; j<numParties; j++){
                auto wireIndices = circuit.getPartyInputs(j);
                for (int k=0; k<wireIndices.size(); k++){
                    computeKeys[wireIndices[k]*numParties + i] = otherInputKeys[inputIndex++];

                }
            }
        }
    }

    _mm_free(myInputKeys);
    _mm_free(otherInputKeys);

}
