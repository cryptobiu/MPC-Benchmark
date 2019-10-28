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


#pragma once
#include <memory>
#include <thread>
#include <boost/thread/thread.hpp>

#define NO_AESNI
#define KEY_SIZE 16

#include <libscapi/include/comm/Comm.hpp>
#include <libscapi/include/infra/Scanner.hpp>
#include <libscapi/include/infra/ConfigFile.hpp>
#include <libscapi/include/cryptoInfra/Protocol.hpp>
#include <libscapi/include/cryptoInfra/SecurityLevel.hpp>
#include <libscapi/include/circuits/GarbledCircuitFactory.hpp>


#ifdef NO_AESNI
#include <ENCRYPTO_utils/timer.h>
#include <ENCRYPTO_utils/socket.h>
#include <ENCRYPTO_utils/channel.h>
#include <ENCRYPTO_utils/typedefs.h>
#include <ENCRYPTO_utils/sndthread.h>
#include <ENCRYPTO_utils/rcvthread.h>
#include <ENCRYPTO_utils/cbitvector.h>
#include <ENCRYPTO_utils/connection.h>
#include <ENCRYPTO_utils/crypto/crypto.h>
#include <ENCRYPTO_utils/parse_options.h>
#include <ENCRYPTO_utils/crypto/ecc-pk-crypto.h>

#include <ot/xormasking.h>
#include <ot/iknp-ot-ext-snd.h>
#include <ot/iknp-ot-ext-rec.h>

#include <libscapi/include/circuits/GarbledBooleanCircuitNoIntrinsics.h>

#else
#include <libscapi/include/circuits/GarbledBooleanCircuit.h>

#endif



struct YaoConfig {
	bool print_output;
	string circuit_type;
	string circuit_file;
	string input_file_1;
	string input_file_2;
	IpAddress sender_ip;
	int sender_port;
	YaoConfig(bool print, string c_file, string input_file_1,
		string input_file_2, string sender_ip_str, int sender_port, string circuit_type) {
		print_output = print;
		circuit_file = c_file;
		this->input_file_1 = input_file_1;
		this->input_file_2 = input_file_2;
		sender_ip = IpAddress::from_string(sender_ip_str);
		this->circuit_type = circuit_type;
		this->sender_port = sender_port;
	};

	YaoConfig(string config_file) {
		string os = "Linux";
		ConfigFile cf(config_file);
		cout<<"after config file"<<endl;
		string str_print_output = cf.Value("", "print_output");
		istringstream(str_print_output) >> std::boolalpha >> print_output;
		string input_section = cf.Value("", "input_section") + "-" + os;
		circuit_file = cf.Value(input_section, "circuit_file");
		input_file_1 = cf.Value(input_section, "input_file_party_1");
		input_file_2 = cf.Value(input_section, "input_file_party_2");
		circuit_type = cf.Value("", "circuit_type");
	}

	YaoConfig() {}
};

/**
* This is an implementation of party one of Yao protocol.
*/
class PartyOne : public MPCProtocol, public SemiHonest{
private:
	int id;
    OTExtSnd *m_sender;			//The OT object that used in the protocol.
    SndThread* m_senderThread;
    RcvThread* m_receiverThread;
    shared_ptr<CSocket> m_socket;
    uint32_t m_nSecParam = 128;
    const int m_cConstSeed = 437398417012387813714564100; // DEBUG ONLY
    const int m_nBaseOTs = 190;
    const int m_nChecks = 380;
    CLock *m_clock;
    crypto *m_crypt;

#ifdef NO_AESNI
	GarbledBooleanCircuitNoIntrinsics * circuit;	//The garbled circuit used in the protocol.
    tuple<byte*, byte*, vector<byte> > values;//this tuple includes the input and output keys (block*) and the translation table (vector)
                                        //to be used after filled by garbling the circuit
#else
	GarbledBooleanCircuit* circuit;	//The garbled circuit used in the protocol.
    tuple<block*, block*, vector<byte> > values;//this tuple includes the input and output keys (block*) and the translation table (vector)
    //to be used after filled by garbling the circuit
#endif
	shared_ptr<CommParty> channel;				//The channel between both parties.
	vector<byte> ungarbledInput;				//Inputs for the protocol
	YaoConfig yaoConfig;


	/**
	* Sends p1 input keys to p2.
	* @param ungarbledInput The boolean input of each wire.
	* @param bs The keys for each wire.
	*/
	void sendP1Inputs(byte* ungarbledInput);

	/**
	* Runs OT protocol in order to send p2 the necessary keys without revealing any other information.
	* @param allInputWireValues The keys for each wire.
	*/
	void runOTProtocol();

public:
	/**
	* Constructor that sets the parameters of the OT protocol and creates the garbled circuit.
	* @param channel The channel between both parties.
	* @param bc The boolean circuit that should be garbled.
	* @param mes The encryption scheme to use in the garbled circuit.
	* @param otSender The OT object to use in the protocol.
	* @param inputForTest
	*/
	PartyOne(int argc, char* argv[]);

	~PartyOne()
	{
//#ifdef NO_AESNI
//        delete [] get<0>(values);
//        delete [] get<1>(values);
//#else
//        //delete inputs and output block arrays
//#endif
//		delete circuit;
//		delete m_sender;
//


	}

	void setInputs(string inputFileName, int numInputs);

    bool hasOffline() override { return false; }
    bool hasOnline() override { return true; }

    void runOnline() override;

	YaoConfig& getConfig() { return yaoConfig; }

	int getID() {return id;}
};

/**
* This is an implementation of party one of Yao protocol.
*/
class PartyTwo : public MPCProtocol, public SemiHonest{
private:
	int id;
    OTExtRec * m_receiver;  //The OT object that used in the protocol.
    shared_ptr<CSocket> m_socket;
    SndThread* m_senderThread;
    RcvThread* m_receiverThread;
    uint32_t m_nSecParam = 128;
    const int m_cConstSeed = 15657566154164561; // DEBUG ONLY
    const int m_nBaseOTs = 190;
    const int m_nChecks = 380;
    CLock *m_clock;
    crypto *m_crypt;

#ifdef NO_AESNI
	GarbledBooleanCircuitNoIntrinsics * circuit;	//The garbled circuit used in the protocol.
#else
	GarbledBooleanCircuit* circuit;	//The garbled circuit used in the protocol.
#endif
	shared_ptr<CommParty> channel;				//The channel between both parties.
	byte* p1Inputs;
	int p1InputsSize;
	bool print_output;					// Indicates if to print the output at the end of the execution or not

	vector<byte> circuitOutput;
	vector<byte> ungarbledInput;
	YaoConfig yaoConfig;
	
	/**
	* Compute the garbled circuit.
	* @param otOutput The output from the OT protocol, which are party two inputs.
	*/
	void computeCircuit(CBitVector *c);

	/**
	* Receive the circuit's garbled tables and translation table.
	*/
	void receiveCircuit();
	/**
	* Receives party one input.
	*/
	void receiveP1Inputs();
	/**
	* Run OT protocol in order to get party two input without revealing any information.
	* @param sigmaArr Contains a byte indicates for each input wire which key to get.
	* @return The output from the OT protocol, party tw oinputs.
	*/

public:
	/**
	* Constructor that sets the parameters of the OT protocol and creates the garbled circuit.
	* @param channel The channel between both parties.
	* @param bc The boolean circuit that should be garbled.
	* @param mes The encryption scheme to use in the garbled circuit.
	* @param otSender The OT object to use in the protocol.
	* @param inputForTest
	*/
	PartyTwo(int argc, char* argv[]);

	~PartyTwo() {
		delete circuit;
		delete m_receiver;

	}

	void setInputs(string inputFileName, int numInputs);

	bool hasOffline() override { return false; }
	bool hasOnline() override { return true; }

    void runOnline() override;

    CBitVector* runOTProtocol(byte* sigmaArr, int arrSize);

	vector<byte> getOutput() {	return circuitOutput; }

	YaoConfig& getConfig() { return yaoConfig; }
    int getID() {return id;}
};