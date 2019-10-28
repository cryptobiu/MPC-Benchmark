/**
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
* Copyright (c) 2016 LIBSCAPI (http://crypto.biu.ac.il/SCAPI)
* This file is part of the SCAPI project.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
* 
* Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
* to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
* and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
* 
* The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
* 
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
* FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
* 
* We request that any publication and/or code referring to and/or based on SCAPI contain an appropriate citation to SCAPI, including a reference to
* http://crypto.biu.ac.il/SCAPI.
* 
* Libscapi uses several open source libraries. Please see these projects for any further licensing issues.
* For more information , See https://github.com/cryptobiu/libscapi/blob/master/LICENSE.MD
*
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
*/



#include <tuple>
#include <libscapi/include/circuits/Compat.h>
#include "YaoParties.hpp"

vector<byte> readInputAsVector(string input_file, int numInputs) {
	auto sc = scannerpp::Scanner(new scannerpp::File(input_file));
	vector<byte> inputVector(numInputs);
	for (int i = 0; i < numInputs; i++) {
		inputVector[i] = (byte) sc.nextInt();
	}
	return inputVector;
}

/*********************************/
/*          PartyOne             */
/*********************************/

PartyOne::PartyOne(int argc, char* argv[]) : MPCProtocol("SemiHonestYao", argc, argv) {
	id = stoi(this->getParser().getValueByKey(arguments, "partyID"));


	YaoConfig yao_config(this->getParser().getValueByKey(arguments, "configFile"));
	this->yaoConfig = yao_config;
	
	//open parties file
	ConfigFile cf(this->getParser().getValueByKey(arguments, "partiesFile"));

	string receiver_ip, sender_ip;
	int sender_port;

//	//get partys IPs and ports data
	sender_port = stoi(cf.Value("", "party_0_port"));
	sender_ip = cf.Value("", "party_0_ip");

	channel = parties[1];

	// create the garbled circuit
#ifdef NO_AESNI
    circuit = new GarbledBooleanCircuitNoIntrinsics(yao_config.circuit_file.c_str());
#else
    circuit = GarbledCircuitFactory::createCircuit(yao_config.circuit_file,
		                GarbledCircuitFactory::CircuitType::FIXED_KEY_FREE_XOR_HALF_GATES, false);
#endif

	setInputs(yao_config.input_file_1, circuit->getNumberOfInputs(1));
    // create the semi honest OT extension sender
	SocketPartyData senderParty(IpAddress::from_string(sender_ip), sender_port+1);
	cout<<"sender ip: "<<senderParty.getIpAddress() <<"port:"<<senderParty.getPort()<<endl;

    m_socket = Listen(senderParty.getIpAddress().to_string(), 7766);
    m_clock = new CLock();
    m_senderThread = new SndThread(m_socket.get(), m_clock);
    m_receiverThread = new RcvThread(m_socket.get(), m_clock);
    m_crypt = new crypto(m_nSecParam, (uint8_t*) this->m_cConstSeed);
	m_sender = new IKNPOTExtSnd(m_crypt, m_receiverThread, m_senderThread);


};

void PartyOne::setInputs(string inputFileName, int numInputs) {
	ungarbledInput = readInputAsVector(inputFileName, numInputs);
}

void PartyOne::sendP1Inputs(byte* ungarbledInput) {
	byte* allInputs = (byte*)std::get<0>(values);
	// get the size of party one inputs
	int numberOfp1Inputs = 0;
	numberOfp1Inputs = circuit->getNumberOfInputs(1);
	int inputsSize = numberOfp1Inputs*KEY_SIZE;
	byte* p1Inputs = new byte[inputsSize];

	// create an array with the keys corresponding the given input.
	int inputStartIndex;
	for (int i = 0; i < numberOfp1Inputs; i++) {
		inputStartIndex = (2 * i + ((int) ungarbledInput[i]))*KEY_SIZE;
		memcpy(p1Inputs + i*KEY_SIZE, allInputs + inputStartIndex, KEY_SIZE);
	}
	// send the keys to p2.
	channel->write(p1Inputs, inputsSize);
	delete p1Inputs;
}

void PartyOne::runOnline() {
	values = circuit->garble();
	// send garbled tables and the translation table to p2.
	auto garbledTables = circuit->getGarbledTables();

	channel->write((byte *) garbledTables, circuit->getGarbledTableSize());
	channel->write(circuit->getTranslationTable().data(), circuit->getNumberOfOutputs());
	// send p1 input keys to p2.
	sendP1Inputs(ungarbledInput.data());

	// run OT protocol in order to send p2 the necessary keys without revealing any information.
	runOTProtocol();
	
}

void PartyOne::runOTProtocol() {
	//Get the indices of p2 input wires.
	int p1InputSize, p2InputSize;
	byte* allInputWireValues = (byte*)std::get<0>(values);
	p1InputSize = circuit->getNumberOfInputs(1);
	p2InputSize = circuit->getNumberOfInputs(2);
//    auto p2inputIndices = circuit->getInputWireIndices(2);
	vector<byte> x0Arr;
	x0Arr.reserve(p2InputSize * KEY_SIZE);
	vector<byte> x1Arr;
	x1Arr.reserve(p2InputSize * KEY_SIZE);
	int beginIndex0, beginIndex1;
	for (int i = 0; i<p2InputSize; i++) {
        beginIndex0 = p1InputSize * 2 * KEY_SIZE + 2 * i*KEY_SIZE;
        beginIndex1 = p1InputSize * 2 * KEY_SIZE + (2 * i + 1)*KEY_SIZE;

		x0Arr.insert(x0Arr.end(), &allInputWireValues[beginIndex0], &allInputWireValues[beginIndex0 + KEY_SIZE]);
		x1Arr.insert(x1Arr.end(), &allInputWireValues[beginIndex1], &allInputWireValues[beginIndex1 + KEY_SIZE]);
	}

    uint64_t numOTs = 100000;
    //bitlength of the values that are transferred - NOTE that when bitlength is not 1 or a multiple of 8, the endianness has to be observed
    uint32_t bitlength = 8;
    uint32_t runs = 1;
    uint32_t nsndvals = 2;
    int m_nNumOTThreads = 1;
    CBitVector delta;
    MaskingFunction *m_fMaskFct = new XORMasking(bitlength, delta);
    CBitVector** X = (CBitVector**) malloc(sizeof(CBitVector*) * nsndvals);

    //creates delta as an array with "numOTs" entries of "bitlength" bit-values and fills delta with random values
    delta.Create(numOTs, bitlength, m_crypt);

    //Create the X values as two arrays with "numOTs" entries of "bitlength" bit-values and resets them to 0
    for(uint32_t i = 0; i < nsndvals; i++) {
        X[i] = new CBitVector();
        X[i]->Create(numOTs, bitlength);
    }

    bool success = m_sender->send(numOTs, bitlength, nsndvals, X,
            Snd_OT, Rec_OT, m_nNumOTThreads, m_fMaskFct);
}

/*********************************/
/*          PartyTwo             */
/*********************************/

PartyTwo::PartyTwo(int argc, char* argv[]) : MPCProtocol("SemiHonestYao", argc, argv){

	id = stoi(this->getParser().getValueByKey(arguments, "partyID"));

	YaoConfig yao_config(this->getParser().getValueByKey(arguments, "configFile"));
	this->yaoConfig = yao_config;

	this->print_output = yaoConfig.print_output;

	//open parties file
	ConfigFile cf(this->getParser().getValueByKey(arguments, "partiesFile"));
	
	string receiver_ip, sender_ip;
	int sender_port;

	//get partys IPs and ports data
	sender_port = stoi(cf.Value("", "party_0_port"));
	sender_ip = cf.Value("", "party_0_ip");

	channel = parties[0];
	// create the garbled circuit
#ifdef NO_AESNI
    circuit = new GarbledBooleanCircuitNoIntrinsics(yao_config.circuit_file.c_str());
#else
    circuit = GarbledCircuitFactory::createCircuit(yao_config.circuit_file,
                                                   GarbledCircuitFactory::CircuitType::FIXED_KEY_FREE_XOR_HALF_GATES, false);
#endif
	setInputs(yao_config.input_file_2,  circuit->getNumberOfInputs(2));
	// create the OT receiver.
	SocketPartyData senderParty(IpAddress::from_string(sender_ip), sender_port+1);

    m_socket = Listen(senderParty.getIpAddress().to_string(), 7766);
    m_clock = new CLock();
    m_senderThread = new SndThread(m_socket.get(), m_clock);
    m_receiverThread = new RcvThread(m_socket.get(), m_clock);

    m_crypt = new crypto(m_nSecParam, (uint8_t*) this->m_cConstSeed);
    m_receiver = new IKNPOTExtRec(m_crypt, m_receiverThread, m_senderThread);


}

void PartyTwo::setInputs(string inputFileName, int numInputs) {
	ungarbledInput = readInputAsVector(inputFileName, numInputs);
}

void PartyTwo::computeCircuit(CBitVector *c) {

	// Get the input of the protocol.
	vector<byte> p2Inputs((byte*)c->GetArr(), (byte*)c->GetArr() + c->GetSize());
	int p2InputsSize = c->GetSize();
	// Get party two input wires' indices.
	vector<byte> allInputs(p1InputsSize + p2InputsSize);
    memcpy(&allInputs[0], p1Inputs, p1InputsSize);
	memcpy(&allInputs[p1InputsSize], p2Inputs.data(), p2InputsSize);

    // compute the circuit.

#ifdef NO_AESNI
    byte* garbledOutput = new byte[KEY_SIZE * 2 * circuit->getNumberOfOutputs()];
	circuit->compute(&allInputs[0], garbledOutput);
#else
    block* garbledOutput = (block *)_aligned_malloc(sizeof(block) * 2 * circuit->getNumberOfOutputs(), SIZE_OF_BLOCK); ;
    circuit->compute((block*)&allInputs[0], garbledOutput);
#endif

	// translate the result from compute.
	circuitOutput.resize(circuit->getNumberOfOutputs());
	circuit->translate(garbledOutput, circuitOutput.data());
}

void PartyTwo::runOnline() {
	// receive tables and inputs
	receiveCircuit();
	receiveP1Inputs();

	// run OT protocol in order to get the necessary keys without revealing any information.
	auto output = runOTProtocol(ungarbledInput.data(), ungarbledInput.size());

	// Compute the circuit.
	computeCircuit(output);

	// we're done print the output
	if (print_output)
	{
		int outputSize = circuit->getNumberOfOutputs();
		cout << "PartyTwo: printing outputSize: " << outputSize << endl;
		for (int i = 0; i < outputSize; i++)
			cout << (int)circuitOutput[i];
		cout << endl;
	}
}

CBitVector* PartyTwo::runOTProtocol(byte* sigmaArr, int arrSize)
{
    //Create an OT input object with the given sigmaArr.
    vector<byte> sigma;
    copy_byte_array_to_byte_vector(sigmaArr, arrSize, sigma, 0);
    int elementSize = 128;
    uint32_t bitlength = 8;
    uint32_t runs = 1;
    uint32_t nsndvals = 2;
    uint64_t numOTs = 100000;
    int m_nNumOTThreads = 1;

    MaskingFunction* m_fMaskFct = new XORMasking(bitlength);
    CBitVector *choices, *response;
    choices->Create((size_t )(numOTs * ceil_log2(nsndvals)), m_crypt);
    response->Create(numOTs, bitlength);
    response->Reset();


    bool success = m_receiver->receive(numOTs, bitlength, nsndvals, choices, response,
            Snd_OT, Rec_OT, m_nNumOTThreads, m_fMaskFct);

    return response;

};

void PartyTwo::receiveCircuit() {

	// receive garbled tables.
	channel->read((byte*)circuit->getGarbledTables(), circuit->getGarbledTableSize());
	byte * translationTable = new byte[circuit->getNumberOfOutputs()];

	// receive translation table.
	channel->read(translationTable, circuit->getNumberOfOutputs());
	std::vector<byte> translationTableVec(translationTable, translationTable + circuit->getNumberOfOutputs());
	
	circuit->setTranslationTable(translationTableVec);
}

void PartyTwo::receiveP1Inputs() {
	p1InputsSize = circuit->getNumberOfInputs(1)*KEY_SIZE;
	p1Inputs = new byte[p1InputsSize];
	channel->read(p1Inputs, p1InputsSize);
}
