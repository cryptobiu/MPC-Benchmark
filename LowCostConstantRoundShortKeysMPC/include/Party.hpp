#pragma once

#include <NTL/ZZ_p.h>
#include <cmath>
#include <libscapi/include/primitives/Prg.hpp>
#include <libscapi/include/cryptoInfra/Protocol.hpp>
#include <libscapi/include/cryptoInfra/SecurityLevel.hpp>
#include <libscapi/include/infra/Measurement.hpp>
#include "Circuit.hpp"
#include "MPCCommunication.hpp"
#include "Utils.hpp"

using namespace NTL;

/**
 * This class represents a party in the Low cost constant round MPC combining BMR and ot protocol.
 */
class Party : public Protocol, SemiHonest, MultiParty{

private:
    int id;                         //Each party gets unique id number
    int keySize;
    bool isLookup;

    u_int32_t numParties;           //Number of parties in the protocol

                                    //Usually this will be (#parties - 1) or (#parties - 1)*2
    Circuit circuit;               //The circuit the protocol computes

    ofstream outputFile;           //The file where the protocol times are written to.

    boost::asio::io_service io_service;      //Used in scapi communication
//    osuCrypto::IOService ios_ot;             //used in LibOTe communication
    vector<ProtocolPartyData*> parties;      //The communication data.

    Utils utils;                             //Utility class that perform some of the protocol functionalities, such as broadcast
    PrgFromOpenSSLAES prg;                   //Used in the protocol in order to get random bytes

    EVP_CIPHER_CTX* aes;                     //Used in the protocol in order to encrypt data
    const EVP_CIPHER* cipher;

    vector<byte> lookupTableAnd;
    vector<byte> lookupTableSplit;

    byte* garbleTableAnd;
    byte* garbleTableSplit;

    vector<byte> outputLambdas;
    vector<byte> inputLambdas;

    vector<byte> inputKeys0;
    vector<byte> inputKeys1;

    byte *publicValues;
    vector<byte> computeKeys;

    //For simulation of all other parties:
    vector<vector<byte>> allInputLambdas;
    vector<vector<byte>> allkeys0;
    vector<vector<byte>> allkeys1;

    vector<byte> inputs, output;
    string otherInputFileName;

    int times, iteration;
    Measurement* timer;


    void garble();

    vector<byte> sampleLambdasAndKeys(vector<byte> & wireKeys0, vector<byte> & wireKeys1);

    void generateGarblingTable(const vector<byte> & wiresLambdas, vector<byte> & wireKeys0, vector<byte> & wireKeys1);

    void sendOutputs(const vector<byte> & wireLambdas);

    void sendInputs(const vector<byte> & wireLambdas);

    void sendKeys(const vector<byte> & wireKeys0, const vector<byte> & wireKeys1);

    void receiveData();

    void openGarble();

    void localComputeCircuit(vector<byte> & computeKeys, byte* publicValues);

    vector<byte> computeOutput(const vector<byte> & computeKeys, byte* publicValues);

public:

    /**
     * Constructor that creates the current protocol party.
     * @param id unique number for this party
     * @param circuit the circuit to compute in the protocol
     * @param partiesFile contains information regarding the communication
     * @param numThreads number of threads to use in the protocol. Usually this will be (#parties - 1) or (#parties - 1)*2.
     * @param outputFile The file where to print the times.
     * @param B bucket size
     */
    Party(int argc, char* argv[]);/*int id, Circuit* circuit, string partiesFile, bool isLookup, int keySize);*/

    /**
     * destructor that deleted all the allocated memory.
     */
    ~Party();

    void run() override;
    bool hasOffline() override {
        return true;
    }
    void runOffline() override;
    bool hasOnline() override {
        return true;
    }
    void runOnline() override;

    /**
     * Offline phase of the protocol.
     */
    void preprocess();

    /**
     * Online phase of the protocol.
     * @param inputs the inputs for this party
     * @return the output of the circuit
     */
    void receiveInputsFromOtherParties(const vector<byte> & inputs);

    //For simulation of all other parties:
    void simulateReceiveInputsFromOtherParties();

    vector<byte> localComputation();

    vector<byte> getOutput() { return output; }

    void setIteration(int iterationNum) { iteration = iterationNum; }

    /**
     * Reads the inputs form the input file
     * @param inputFileName contains the input of this party.
     * @return the inputs of this party
     */
    vector<byte> readInputs(string inputFileName);

    /**
     * Initialize the times in order make all the parties ready for the next computation.
     * This will make sure no party will wait until the others will start computation.
     */
    void initTimes();

};
