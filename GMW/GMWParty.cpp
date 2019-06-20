//
// Created by moriya on 08/01/17.
//

#include "GMWParty.h"

GMWParty::GMWParty(int argc, char* argv[]) : MPCProtocol("GMW", argc, argv)
{
    circuit = make_shared<Circuit>();
    circuit->readCircuit(this->getParser().getValueByKey(arguments, "circuitFile"));

    id = stoi(this->getParser().getValueByKey(arguments, "partyID"));
    times = stoi(this->getParser().getValueByKey(arguments, "internalIterationsNumber"));

    vector<string> subTaskNames{"Offline", "GenerateTriples", "Online", "InputSharing", "ComputeCircuit"};
    this->timer->addTaskNames(subTaskNames);
    int numThreads = stoi(this->getParser().getValueByKey(arguments, "numThreads"));
    inputFileName = this->getParser().getValueByKey(arguments, "inputFile");
    auto partiesFile = this->getParser().getValueByKey(arguments, "partiesFile");
    initOT(partiesFile);

    if (parties.size() <= numThreads){
        this->numThreads = parties.size();
        numPartiesForEachThread = 1;
    } else{
        this->numThreads = numThreads;
        numPartiesForEachThread = (parties.size() + numThreads - 1)/ numThreads;
    }

}

void GMWParty::initOT(string &configFile)
{
    //open file
    ConfigFile cf(configFile);

    string portString, ipString;
    vector<int> ports(numParties);
    vector<string> ips(numParties);

    for (int i = 0; i < numParties; i++)
    {
        portString = "party_" + to_string(i) + "_port";
        ipString = "party_" + to_string(i) + "_ip";

        //get partys IPs and ports data
        ports[i] = stoi(cf.Value("", portString));
        ips[i] = cf.Value("", ipString);
    }

    SocketPartyData me, other;

    for (int i=0; i<numParties; i++)
    {
        if (i < id)
        {
            receiver = new OTExtensionBristolReceiver(ips[i], ports[i]+ numParties -2 + id,
                    true, nullptr);
            sender = new OTExtensionBristolSender(ports[id] + numParties - 1 + i, true, nullptr);
        }
        else if (i > id)
        {
            OTBatchSender* sender = new OTExtensionBristolSender(ports[id] + numParties - 2 + i, true, nullptr);
            OTBatchReceiver* receiver = new OTExtensionBristolReceiver(ips[i], ports[i]+ numParties -1 + id,
                    true, nullptr);

        }
    }
}

void GMWParty::run(){

    for (currentIteration = 0; currentIteration<times; currentIteration++) {
        //Run the offline phase of the protocol
        timer->startSubTask("Offline", currentIteration);
        runOffline();
        timer->endSubTask("Offline", currentIteration);
        auto inputSize = circuit->getPartyInputs(id).size(); //indices of my input wires
        myInputBits.resize(inputSize, 0); //input bits, will be adjusted to my input shares
        //read my input from the input file
        readInputs();
        //Run te online phase of the protocol
        timer->startSubTask("Online", currentIteration);
        runOnline();
        timer->endSubTask("Online", currentIteration);
    }

}

void GMWParty::runOffline(){
    timer->startSubTask("GenerateTriples", currentIteration);
    generateTriples();
    timer->endSubTask("GenerateTriples", currentIteration);
	auto inputSize = circuit->getPartyInputs(id).size(); //indices of my input wires
	myInputBits.resize(inputSize, 0); //input bits, will be adjusted to my input shares
									  //read my input from the input file
}

void GMWParty::runOnline(){
    timer->startSubTask("InputSharing", currentIteration);
    inputSharing();
    timer->endSubTask("InputSharing", currentIteration);
    timer->startSubTask("ComputeCircuit", currentIteration);
    computeCircuit();
    timer->endSubTask("ComputeCircuit", currentIteration);
}

void GMWParty::generateTriples(){

    /*
     * Generates a multiplication triple (a0 ^ a1)(b0 ^ b1) = (c0 ^ c1) for each and gate for each party.
     * This is done by comouting 2 random OTs between each pair of parties.
     */

    //There are 4 values for each multiplication triple (a, b, u, v)
    //There is a multiplication triple for each party and for each AND gate.
    int size = parties.size()*circuit->getNrOfAndGates();
    aArray.resize(size);
    bArray.resize(size);
    cArray.resize(size);
    vector<byte> sigma(circuit->getNrOfAndGates());
    vector<byte> x0, x1, xSigma;
    int position;
    byte v, u;

    PrgFromOpenSSLAES prg;
    auto key =prg.generateKey(128);
    prg.setKey(key);

    vector<thread> threads(numThreads);

	//Split the work to threads. Each thread gets some parties to work on.
    for (int t=0; t<numThreads; t++) {
        if ((t + 1) * numPartiesForEachThread <= parties.size()) {
            threads[t] = thread(&GMWParty::generateTriplesForParty, this, ref(prg), t * numPartiesForEachThread,
                                (t + 1) * numPartiesForEachThread);
        } else {
            threads[t] = thread(&GMWParty::generateTriplesForParty, this, ref(prg), t * numPartiesForEachThread, parties.size());
        }
    }
    for (int t=0; t<numThreads; t++){
        threads[t].join();
    }
}

void GMWParty::generateTriplesForParty(PrgFromOpenSSLAES & prg, int first, int last){

    vector<byte> sigma(circuit->getNrOfAndGates());
    vector<byte> x0, x1, xSigma;
    byte v, u;

    shared_ptr<OTBatchSOutput> sOutput;
    shared_ptr<OTBatchROutput> rOutput;

    for (int i=first; i < last; i++) {
		//sample random value for each and gate
        mtx.lock();
        prg.getPRGBytes(sigma, 0, sigma.size());
        mtx.unlock();
        for (int i = 0; i < sigma.size(); i++) {
            sigma[i] = sigma[i] % 2; //sigma should be 0/1
        }
        //If this id is lower than the other id, run the sender role in the OT,
        //else, run the receiver role.
        if (id < i) {

            //Play the sender role of the OT and then the receiver role.
            OTExtensionRandomizedSInput sInput(circuit->getNrOfAndGates(), 8);
            sOutput = this->sender->transfer(&sInput);

            OTExtensionRandomizedRInput rInput(sigma, 8);
            rOutput = this->receiver->transfer(&rInput);

        } else {
            //Play the receiver role in the OT and then the sender role.
            OTExtensionRandomizedRInput input(sigma, 8);
            rOutput = this->receiver->transfer(&input);

            OTExtensionRandomizedSInput sInput(circuit->getNrOfAndGates(), 8);
            sOutput = this->sender->transfer(&sInput);
        }

        /* The sender output of the random ot are x0, x1.
         * Set b = x0 ^ x1
         *     v = x0
         * The receiver output of the random ot is u = Xa.
         *
         */
#ifndef _WIN32
        x0 = ((OTExtensionBristolRandomizedSOutput *) sOutput.get())->getR0Arr();
        x1 = ((OTExtensionBristolRandomizedSOutput *) sOutput.get())->getR1Arr();
        xSigma = ((OTExtensionBristolROutput *) rOutput.get())->getXSigma();
#else
		x0 = ((OTExtensionRandomizedSOutput *)sOutput.get())->getR0Arr();
		x1 = ((OTExtensionRandomizedSOutput *)sOutput.get())->getR1Arr();
		xSigma = ((OTOnByteArrayROutput *)rOutput.get())->getXSigma();
#endif
        for (int j = 0; j < circuit->getNrOfAndGates(); j++) {
            //convert the output of the random ot to 0/1.
            x0[j] %= 2;
            x1[j] %= 2;
            xSigma[j] %= 2;

            v = x0[j];                          // v
            bArray[j*parties.size() + i] = v ^ x1[j];   // b
            aArray[j*parties.size() + i] = sigma[j];    // a
            u = xSigma[j];                      // u
            cArray[j*parties.size() + i] = ((v ^ x1[j]) * sigma[j]) ^ v ^ u; // c = (ab) ^ u ^ v.
        }
    }
}
void GMWParty::inputSharing(){
	auto myInputWires = circuit->getPartyInputs(id); //indices of my input wires
    wiresValues.resize(circuit->getNrOfInput(), 0); //all shares of input wires

    PrgFromOpenSSLAES prg;
    auto key =prg.generateKey(128);
    prg.setKey(key);

	//Split the work to threads. Each thread gets some parties to work on.
    vector<thread> threads(numThreads);
    for (int t=0; t<numThreads; t++) {
        if ((t + 1) * numPartiesForEachThread <= parties.size()) {
            threads[t] = thread(&GMWParty::sendSharesToParties, this, ref(prg), ref(myInputBits), t * numPartiesForEachThread,
                                (t + 1) * numPartiesForEachThread);
        } else {
            threads[t] = thread(&GMWParty::sendSharesToParties, this, ref(prg), ref(myInputBits),
                    t * numPartiesForEachThread, parties.size());
        }
    }
    for (int t=0; t<numThreads; t++){
        threads[t].join();
    }

    //Set my input shares in the big shares array
    for (int j=0; j<myInputBits.size(); j++){
        wiresValues[myInputWires[j]] = myInputBits[j];
    }

}

void GMWParty::sendSharesToParties(PrgFromOpenSSLAES & prg, vector<byte> & myInputBits, int first, int last){
    int inputSize = myInputBits.size();
    vector<byte> myShares(inputSize, 0); //the shares to send to the other parties
    vector<byte> otherShares(inputSize, 0); //the shares to receive from the other parties
    vector<int> otherInputWires; //indeices of the other party's input wires

    for (int i=first; i < last; i++) {
        //sample random values to be the shares of the other party.
        mtx.lock();
        prg.getPRGBytes(myShares, 0, inputSize);
        mtx.unlock();
        //convert each value to 0/1 and adjust my shares with the sampled values.
        for (int j=0; j<inputSize; j++){
            myShares[j] %= 2;
            mtx.lock();
            myInputBits[j] ^= myShares[j];
            mtx.unlock();
        }

        if (id < parties[i]->getID()) {
            //send shares to my input bits
            parties[i]->getChannel()->write(myShares.data(), myShares.size());

            //receive shares from the other party and set them in the shares array
            receiveShares(otherInputWires, otherShares, i);

        } else{
            //receive shares from the other party and set them in the shares array
            receiveShares(otherInputWires, otherShares, i);

            //send shares to my input bits
            parties[i]->getChannel()->write(myShares.data(), myShares.size());

        }
    }
}
void GMWParty::receiveShares(vector<int> & otherInputWires, vector<byte> & otherShares, int i)  {
    //Receive shares from other party
    otherInputWires = circuit->getPartyInputs(parties[i]->getID());
    otherShares.resize(otherInputWires.size(), 0);
    parties[i]->getChannel()->read(otherShares.data(), otherShares.size());

    //Set the given shares in the big shares array.
    for (int j=0; j<otherShares.size(); j++){
        wiresValues[otherInputWires[j]] = otherShares[j];
    }
}

void GMWParty::readInputs() {
    //Read the input from the given input file
    ifstream myfile;
    int input;

    myfile.open(inputFileName);
    int size = myInputBits.size();

    for (int i = 0; i<size; i++){
        myfile >> input;
        myInputBits[i] = (byte)input;
    }
    myfile.close();
}

vector<byte>& GMWParty::computeCircuit(){
    Gate gate;
    wiresValues.resize(circuit->getNrOfInput() + circuit->getNrOfGates(), 0);
    vector<bool> isWireReady(circuit->getNrOfInput() + circuit->getNrOfGates(), false); //indicates for each wire if it has value or not yet.

    for (int i=0; i<circuit->getNrOfInput(); i++){
        isWireReady[i] = true;
    }

    auto depths = circuit->getDepths();

    int layer=0;
    int andGatesCounter = 0, firstAndGateToRecompute = -1, numAndGatesComputed = 0, andGatesComputedCounter;
    vector<CBitVector> myD(parties.size()), myE(parties.size());

    for(int i=0; i<parties.size(); i++){
        myD[i].Create(depths[layer]);
        myE[i].Create(depths[layer]);
    }

    byte x, y, a, b;
	int index = 0;

    byte* aArrayPosition = aArray.data();
    byte* bArrayPosition = bArray.data();
    auto gatesIterator = circuit->getGates().begin();
    for (int i=0; i<circuit->getNrOfGates(); i++){
        gate = *gatesIterator;
        gatesIterator++;
        
        //In case the gate is not ready, meaning that at least one of its input wires wasn't computed yet,
        //We should run the recompute function in order to compute all gates till here.
        //After that, the input wire will be ready.
        if (!isWireReady[gate.inputIndex1] || ((gate.inFan != 1) && !isWireReady[gate.inputIndex2])) {
            recomputeAndGatesWithThreads(firstAndGateToRecompute, myD, myE, i, isWireReady, numAndGatesComputed, index);
            if (layer < depths.size()-1 ) {
                layer++;
                for (int j = 0; j < parties.size(); j++) {
                    myD[j].Create(depths[layer]);
                    myE[j].Create(depths[layer]);
                }
            }
            numAndGatesComputed += index;
            index = 0;
            firstAndGateToRecompute = -1;
        }
        //The gate is ready to be computed, so continue computing:
        // xor gate
        if (gate.gateType == 6) {

             //in case of xor gate the output share is the xor of the input shares
            wiresValues[gate.outputIndex] = wiresValues[gate.inputIndex1] ^ wiresValues[gate.inputIndex2];
            isWireReady[gate.outputIndex] = true;
        //not gate
        } else if (gate.gateType == 12){

            if (id == 0) {
                //in case of xor gate the output share is the xor of the input shares
                wiresValues[gate.outputIndex] = 1 - wiresValues[gate.inputIndex1];
            } else {
                wiresValues[gate.outputIndex] = wiresValues[gate.inputIndex1];
            }
            isWireReady[gate.outputIndex] = true;
        //and/or gate
        } else if (gate.gateType == 1 || gate.gateType == 7) {

            if (firstAndGateToRecompute == -1)
                firstAndGateToRecompute = i;

            //In case of or gate, (a | b) = ~(~a^~b).
            //not gate can be computed by p0 change its bit.
            // So, in order to compute or p0 first change its input bit, than compute and gate and then p0 again change the output bit.
            if (gate.gateType == 7 && id == 0) {
                wiresValues[gate.inputIndex1] = 1 - wiresValues[gate.inputIndex1];
                wiresValues[gate.inputIndex2] = 1 - wiresValues[gate.inputIndex2];
            }

            //The output share of the and gate is calculated by x1^y1 + x1y2 + x1y3 + ...
            //If the number of parties is odd, the calculation of x*y is done by the multiplication triples computation.
            // If the number is even, the value of x*y is reset so it should be computed again:
            if (parties.size() % 2 == 0) {
                wiresValues[gate.outputIndex] = wiresValues[gate.inputIndex1] * wiresValues[gate.inputIndex2];
            }

            //Compute other multiplication values
            //for all parties, prepare arrays to hold d, e, values.
            //These values will be sent to the other party
            for (int j=0; j<parties.size(); j++){
                //Calculate d = x^a, e = y^b
                x  = wiresValues[gate.inputIndex1];
                a = *aArrayPosition;
                y = wiresValues[gate.inputIndex2];
                b = *bArrayPosition;
                myD[j].SetBit(index, x ^ a);
                myE[j].SetBit(index, y ^ b);
                aArrayPosition++;
                bArrayPosition++;
            }
            index++;
            andGatesCounter++;

            //Flip again the input bit in order to remain true for other gates.
            if (gate.gateType == 7 && id == 0){
                wiresValues[gate.inputIndex1] = 1 - wiresValues[gate.inputIndex1];
                wiresValues[gate.inputIndex2] = 1 - wiresValues[gate.inputIndex2];
            }
        }

    }

    //Recompute the last and gates
    if (firstAndGateToRecompute != -1){
        recomputeAndGatesWithThreads(firstAndGateToRecompute, myD, myE, circuit->getNrOfGates(), isWireReady, numAndGatesComputed, index);
    }

    //after computing the circuit, calculate the output values by receiving the shares;
    return revealOutput();
}

void GMWParty::recomputeAndGatesWithThreads(int & firstAndGateToRecompute, vector<CBitVector> & myD, vector<CBitVector> & myE, int i,
                                            vector<bool> & isWireReady, int & numAndGatesComputed, int & numAndGatesInRound){
    vector<thread> threads(numThreads);
	//Split the work to threads. Each thread gets some parties to work on.
    for (int t=0; t<numThreads; t++) {
        if ((t + 1) * numPartiesForEachThread <= parties.size()) {
            threads[t] = thread(&GMWParty::recomputeAndGates, this, ref(firstAndGateToRecompute), ref(myD),
                                ref(myE), i, ref(isWireReady), numAndGatesComputed, ref(numAndGatesInRound),
                                t * numPartiesForEachThread, (t + 1) * numPartiesForEachThread);
        } else {
            threads[t] = thread(&GMWParty::recomputeAndGates, this, ref(firstAndGateToRecompute), ref(myD),
                                ref(myE), i, ref(isWireReady), numAndGatesComputed, ref(numAndGatesInRound),
                                t * numPartiesForEachThread, parties.size());
        }
    }
    for (int t=0; t<numThreads; t++){
        threads[t].join();
    }
}


void GMWParty::recomputeAndGates(int firstAndGateToRecompute, vector<CBitVector> & myD, vector<CBitVector> & myE, int i,
                                 vector<bool> & isWireReady, int numAndGatesComputed, int & numAndGatesInRound, int first, int last) {
    Gate recomputeGate;
    byte d, e, z;
    int index;
    CBitVector otherD, otherE;

    vector<byte> threadOutput(numAndGatesInRound, 0);
    int recomputeAndGatesCounter;
    for (int j=first; j < last; j++){
        
        otherD.CreateinBytes(myD[j].GetSize());
        otherE.CreateinBytes(myE[j].GetSize());
        //The party with the lower id will send its bytes first
//        auto start = chrono::high_resolution_clock::now();
        if (id < parties[j]->getID()) {
            //send my d ,e
            parties[j]->getChannel()->write(myD[j].GetArr(), myD[j].GetSize());
            parties[j]->getChannel()->write(myE[j].GetArr(), myE[j].GetSize());
            //receive other d, e
            parties[j]->getChannel()->read(otherD.GetArr(), otherD.GetSize());
            parties[j]->getChannel()->read(otherE.GetArr(), otherE.GetSize());
        } else {
            //receive other d, e
            parties[j]->getChannel()->read(otherD.GetArr(), otherD.GetSize());
            parties[j]->getChannel()->read(otherE.GetArr(), otherE.GetSize());
            //send my d ,e
            parties[j]->getChannel()->write(myD[j].GetArr(), myD[j].GetSize());
            parties[j]->getChannel()->write(myE[j].GetArr(), myE[j].GetSize());
        }
        //Go on each and gate in the ot and compute its output share.
        recomputeAndGatesCounter = 0;
        for (int k=firstAndGateToRecompute; k < i; k++){
            recomputeGate = circuit->getGates()[k];

            if (recomputeGate.gateType == 1 || recomputeGate.gateType == 7) {

                //d = d1^d2
                d = myD[j].GetBit(recomputeAndGatesCounter) ^ otherD.GetBit(recomputeAndGatesCounter);
                //e = e1^e2
                e = myE[j].GetBit(recomputeAndGatesCounter) ^ otherE.GetBit(recomputeAndGatesCounter);
                //z = db ^ ea ^c ^ de
                index = (numAndGatesComputed + recomputeAndGatesCounter) * parties.size() + j;
                z = d * bArray[index];
                z = z ^ (e * aArray[index]);
                z = z ^ cArray[index];
                if (id < parties[j]->getID()) {
                    z = z ^ (d * e);
                }
                threadOutput[recomputeAndGatesCounter] ^= z;
                recomputeAndGatesCounter++;
            }

        }
    }

    index = 0;
    for (int k=firstAndGateToRecompute; k < i; k++) {

        recomputeGate = circuit->getGates()[k];
        if (recomputeGate.gateType == 1 || recomputeGate.gateType == 7) {
            mtx.lock();
            wiresValues[recomputeGate.outputIndex] ^= threadOutput[index++];
            isWireReady[recomputeGate.outputIndex] = true;
            mtx.unlock();

        }
        if (recomputeGate.gateType == 7 && id == 0 && last == parties.size()) {
            mtx.lock();
            wiresValues[recomputeGate.outputIndex] = 1 - wiresValues[recomputeGate.outputIndex];
            mtx.unlock();
        }
    }
}

vector<byte>& GMWParty::revealOutput() {
    vector<int> myOutputIndices = circuit->getPartyOutputs(id);
    int myOutputSize = myOutputIndices.size();
    output.resize(myOutputSize);
    for (int i=0; i<myOutputSize; i++){
        output[i] = wiresValues[myOutputIndices[i]];
    }
    vector<thread> threads(numThreads);
	//Split the work to threads. Each thread gets some parties to work on.
    for (int t=0; t<numThreads; t++) {
        if ((t + 1) * numPartiesForEachThread <= parties.size()) {
            threads[t] = thread(&GMWParty::revealOutputFromParty, this, ref(output), t * numPartiesForEachThread,
                                (t + 1) * numPartiesForEachThread);
        } else {
            threads[t] = thread(&GMWParty::revealOutputFromParty, this, ref(output), t * numPartiesForEachThread,
                                parties.size());
        }
    }
    for (int t=0; t<numThreads; t++){
        threads[t].join();
    }
    return output;
}

void GMWParty::revealOutputFromParty(vector<byte> & output, int first, int last){
    vector<int> otherOutputsIndices;
    vector<byte> otherOutputstoSend;
    vector<byte> otherOutputstoReceive(output.size());
	//send output shares to each party that needs it
    for (int i=first; i < last; i++){
		//get the output wires of the party
        otherOutputsIndices = circuit->getPartyOutputs(parties[i]->getID());
        otherOutputstoSend.resize(otherOutputsIndices.size());
		//fill the array with the shares of the output wires.
        for (int j=0; j<otherOutputsIndices.size(); j++){
            otherOutputstoSend[j] = wiresValues[otherOutputsIndices[j]];
        }
        if (id < parties[i]->getID()) {
			//send my shares to the other party
            parties[i]->getChannel()->write(otherOutputstoSend.data(), otherOutputstoSend.size());
			//receive shares from the pther party
            parties[i]->getChannel()->read(otherOutputstoReceive.data(), otherOutputstoReceive.size());
        } else{
			//receive shares from the pther party
            parties[i]->getChannel()->read(otherOutputstoReceive.data(), otherOutputstoReceive.size());
			//send my shares to the other party
            parties[i]->getChannel()->write(otherOutputstoSend.data(), otherOutputstoSend.size());

        }
		//xor the output shares
        mtx.lock();
        for (int j=0; j<output.size() ; j++){
            output[j] ^= otherOutputstoReceive[j];
        }
        mtx.unlock();

    }
}


vector<byte> GMWParty::getOutput()
{
    return output;
}