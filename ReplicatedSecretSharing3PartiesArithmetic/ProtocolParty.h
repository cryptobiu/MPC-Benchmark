#ifndef PROTOCOLPARTY_H_
#define PROTOCOLPARTY_H_

#include <stdlib.h>
#include <libscapi/include/primitives/Matrix.hpp>
#include <libscapi/include/circuits/ArithmeticCircuit.hpp>
#include <libscapi/include/comm/MPCCommunication.hpp>
#include <libscapi/include/cryptoInfra/Protocol.hpp>
#include <libscapi/include/infra/Measurement.hpp>
#include <libscapi/include/primitives/Mersenne.hpp>
#include "HashEncrypt.h"
#include <libscapi/include/infra/Common.hpp>
#include <thread>

#define flag_print false
#define flag_print_timings true
#define flag_print_output true

#define N 3

using namespace std;
using namespace std::chrono;

template <class FieldType>
class ProtocolParty : public Protocol, public HonestMajority, public ThreeParty{
private:
    /**
     * N - number of parties
     * T - number of malicious
     * M - number of gates
     */
    Measurement* timer;
    int currentCirciutLayer = 0;
    int M, m_partyId;
    int numOfInputGates, numOfOutputGates;
    int times; //number of times to run the run function
    int iteration; //number of the current iteration
    string inputsFile, outputFile;
    FieldType inv_3;
    int LEFT, RIGHT;
    FieldType num_2; // number 2 in the field
    FieldType num_0; // number 0 in the field
    int fieldByteSize;



    vector<shared_ptr<ProtocolPartyData>> parties; // array of channels
    boost::asio::io_service io_service;
    ArithmeticCircuit circuit;
    vector<FieldType> gateShareArr; // my share of the gate (for all gates)
    vector<FieldType> alpha;
    vector<FieldType> random_for_inputs;

    vector<FieldType> a_triple;
    vector<FieldType> b_triple;
    vector<FieldType> c_triple;
    vector<FieldType> r_for_verify;

    vector<FieldType> x_triple;
    vector<FieldType> y_triple;
    vector<FieldType> z_triple;
    vector <FieldType> beta_triple;

    int shareIndex; // number of shares for inputs
    int mult_count = 0;

    vector<long> myInputs;
    string s;

    shared_ptr<CommParty> leftChannel; // the channel with party i minus 1
    shared_ptr<CommParty> rightChannel; // the channel with party i plus 1

    TemplateField<FieldType>* field;

public:
    ProtocolParty(int argc, char* argv[]);

    /**
     * This method runs the protocol:
     * 2. Generate Randomness
     * 3. Input Preparation
     * 4. Computation Phase
     * 5. Verification Phase
     * 6. Output Phase
     */
    void run() override;

    virtual bool hasOffline() {
        return true;
    }


    virtual bool hasOnline() override {
        return true;
    }

    /**
     * This method runs the protocol:
     * Generate Randomness
     *
     */
    virtual void runOffline() override;

    /**
     * This method runs the protocol:
     * Input Preparation
     * Computation Phase
     * Verification Phase
     * Output Phase
     */
    virtual void runOnline() override;

    void roundFunctionSync(vector<vector<byte>> &sendBufs, vector<vector<byte>> &recBufs, int round);
    void exchangeData(vector<vector<byte>> &sendBufs,vector<vector<byte>> &recBufs, int first, int last);
    void sendNext(vector<byte> &sendBufs, vector<byte> &recBufs);

    /**
     * This method reads text file and inits a vector of Inputs according to the file.
     */
    void readMyInputs();

    /**
     * In case the user use the protocol with the offline/online mode, he should also update the iteration number.
     */
    void setIteration(int iteration) {
        this->iteration = iteration;
    }

    /**
     * We describe the protocol initialization.
     * In particular, some global variables are declared and initialized.
     */
    void initializationPhase();

    /**
     * this method prepares all the randomness which required in the protocol.
     */
    void generateRandomness31Bits();

    /**
     * this method prepares all the randomness which required in the protocol.
     */
    void generateRandomness61Bits();

    /**
     * this method prepares the c in each triple by multiplying a and b
     */
    void generateCForTriples(vector<FieldType>& alpha_for_triple, int numOfMult);

    /**
     * this method prepare the gate share array according the inputs and the shares.
     */
    void inputPreparation();

    /**
     * Walk through the circuit and evaluate the gates. Always take as many gates at once as possible,
     * i.e., all gates whose inputs are ready.
     * We first process all random gates, then alternately process addition and multiplication gates.
     */
    void computationPhase();

    /**
     * Process all additions which are ready.
     * Return number of processed gates.
     */
    int processNotMult();

    /**
     * Process all multiplications which are ready.
     * Return number of processed gates.
     */
    // int processMultiplications(vector<FieldType>& x, vector<FieldType>& y, vector<FieldType>& results, vector<FieldType>& alpha_for_mult, int begin_alpha,
    //                           int sizeOfSendBufsElements, int begin, int end);

    int processMultiplications();

    /**
     * this method check if the triples are currect.
     */
    void verification(vector<FieldType>& x_triple, vector<FieldType>& y_triple, vector<FieldType>& z_triple,
                          vector<FieldType>& a_triple, vector<FieldType>& b_triple, vector<FieldType>& c_triple, int numOfMult);

    /**
     * this method open the shares and reconstructs the secrets.
     */
    void openShare(int numOfRandomShares, vector<FieldType> &shares, vector<FieldType> &secrets);

    /**
     * this method generate common key between the parties.
     */
    vector<byte> generateCommonKey(vector<FieldType>& aesArray);

    /**
     * this method sends the results from verification phase.
     */
    void comparingViews(vector<FieldType>& hi,vector<FieldType>& hiPlus1,vector<FieldType>& hiMinus1,
                        int NrOfMultiplicationGates,  HashEncrypt& hashObj1, HashEncrypt& hashObj2,
                        HashEncrypt& hashObj3, HashEncrypt& hashObj4);

    /**
     * Walk through the circuit and reconstruct output gates.
     */
    void outputPhase();

    ~ProtocolParty();
};

template <class FieldType>
ProtocolParty<FieldType>::ProtocolParty(int argc, char* argv[]) : Protocol("Replicated secret sharing 3 parties arithmetic", argc, argv) {

    this->times = stoi(this->getParser().getValueByKey(arguments, "internalIterationsNumber"));

    string fieldType = this->getParser().getValueByKey(arguments, "fieldType");
    if(fieldType.compare("ZpMersenne") == 0)
    {
        field = new TemplateField<FieldType>(2147483647);
    }
    else if(fieldType.compare("ZpMersenne61") == 0)
    {
        field = new TemplateField<FieldType>(0);
    }
    this->inputsFile = this->getParser().getValueByKey(arguments, "inputFile");
    this->outputFile = this->getParser().getValueByKey(arguments, "outputFile");

    m_partyId = stoi(this->getParser().getValueByKey(arguments, "partyID"));

    vector<string> subTaskNames{"Offline", "GenerateRandomness", "Online", "InputPreparation", "ComputationPhase", "Verification", "OutputPhase"};
    timer = new Measurement(*this, subTaskNames);
    s = to_string(m_partyId);
    circuit.readCircuit(this->getParser().getValueByKey(arguments, "circuitFile").c_str());
    circuit.reArrangeCircuit();
    M = circuit.getNrOfGates();
    numOfInputGates = circuit.getNrOfInputGates();
    numOfOutputGates = circuit.getNrOfOutputGates();
    myInputs.resize(numOfInputGates);
    shareIndex = numOfInputGates;

    parties = MPCCommunication::setCommunication(io_service, m_partyId, N,
                this->getParser().getValueByKey(arguments, "partiesFile"));

    int R = 0, L = 1; // TO DO: communication

    if(m_partyId == 1)
    {
        R = 1;
        L = 0;
    }

    leftChannel = parties[L]->getChannel();
    rightChannel = parties[R]->getChannel();

    string tmp = "init times";

    byte tmpBytes[20];
    for (int i=0; i<parties.size(); i++){
        if (parties[i]->getID() < m_partyId){
            parties[i]->getChannel()->write(tmp);
            parties[i]->getChannel()->read(tmpBytes, tmp.size());
        } else {
            parties[i]->getChannel()->read(tmpBytes, tmp.size());
            parties[i]->getChannel()->write(tmp);
        }
    }

    readMyInputs();

    auto t1 = high_resolution_clock::now();
    initializationPhase();

    auto t2 = high_resolution_clock::now();

    auto duration = duration_cast<milliseconds>(t2-t1).count();
    if(flag_print_timings) {
        cout << "time in milliseconds initializationPhase: " << duration << endl;
    }
}

template <class FieldType>
void ProtocolParty<FieldType>::readMyInputs()
{
    ifstream myfile;
    long input;
    int i =0;
    myfile.open(inputsFile);
    do {
        myfile >> input;
        myInputs[i] = input;
        i++;
    } while(!(myfile.eof()));
    myfile.close();

}

/**
     * Executes the protocol.
     */
template <class FieldType>
void ProtocolParty<FieldType>::run() {
    for (iteration=0; iteration<times; iteration++){
        timer->startSubTask("Offline", iteration);
        runOffline();
        timer->endSubTask("Offline", iteration);

        timer->startSubTask("Online", iteration);
        runOnline();
        timer->endSubTask("Online", iteration);
    }
}

template <class FieldType>
void ProtocolParty<FieldType>::runOffline() {

    auto t1 = high_resolution_clock::now();
    timer->startSubTask("GenerateRandomness", iteration);
    if(fieldByteSize > 4) {
        generateRandomness61Bits();
    } else {
        generateRandomness31Bits();
    }
    timer->endSubTask("GenerateRandomness", iteration);
    auto t2 = high_resolution_clock::now();

    auto duration = duration_cast<milliseconds>(t2-t1).count();
    if(flag_print_timings) {
        cout << "time in milliseconds  generateRandomness: " << duration << endl;
    }
}

template <class FieldType>
void ProtocolParty<FieldType>::runOnline() {
    auto t1 = high_resolution_clock::now();
    timer->startSubTask("InputPreparation", iteration);
    inputPreparation();
    timer->endSubTask("InputPreparation", iteration);
    auto t2 = high_resolution_clock::now();

    auto duration = duration_cast<milliseconds>(t2-t1).count();
    if(flag_print_timings) {
        cout << "time in milliseconds   inputPreparation: " << duration << endl;
    }


    t1 = high_resolution_clock::now();
    timer->startSubTask("ComputationPhase", iteration);
    computationPhase();
    timer->endSubTask("ComputationPhase", iteration);


    t2 = high_resolution_clock::now();

    duration = duration_cast<milliseconds>(t2-t1).count();
    if(flag_print_timings) {
        cout << "time in milliseconds   computationPhase: " << duration << endl;
    }


    t1 = high_resolution_clock::now();

    timer->startSubTask("Verification", iteration);
    if(circuit.getNrOfMultiplicationGates() > 0) {

        if(fieldByteSize <= 4) {
            verification(x_triple, y_triple, z_triple, a_triple, b_triple, c_triple, 2 * circuit.getNrOfMultiplicationGates());
        } else {
            verification(x_triple, y_triple, z_triple, a_triple, b_triple, c_triple, circuit.getNrOfMultiplicationGates());
        }
    }
    timer->endSubTask("Verification", iteration);


    t2 = high_resolution_clock::now();

    duration = duration_cast<milliseconds>(t2-t1).count();
    if(flag_print_timings) {
        cout << "time in milliseconds   verification: " << duration << endl;
    }

    t1 = high_resolution_clock::now();
    timer->startSubTask("OutputPhase", iteration);
    outputPhase();
    timer->endSubTask("OutputPhase", iteration);


    t2 = high_resolution_clock::now();

    duration = duration_cast<milliseconds>(t2-t1).count();
    if(flag_print_timings) {
        cout << "time in milliseconds   outputPhase: " << duration << endl;
    }
}

template <class FieldType>
void ProtocolParty<FieldType>::initializationPhase()
{
    /**
     * The indexes in gate share arr:
     * for gates[k] :
     *      gateShareArr[2*k] = s
     *      gateShareArr[2*k+1] = t
     */
    gateShareArr.resize((M - circuit.getNrOfOutputGates())*2); // my share of the gate (for all gates)

    inv_3 = (field->GetElement(1))/(field->GetElement(3)); // calculate the inverse of 3 in the field

    fieldByteSize = field->getElementSizeInBytes();

    LEFT = (m_partyId - 1) % 3; // the number of party i Minus 1
    RIGHT = (m_partyId + 1) % 3; // the number of party i Plus 1

    if(m_partyId == 0) {
        LEFT = 2;
        RIGHT = 1;
    }

    num_2 = (field->GetElement(2));

    num_0 = (field->GetElement(0));

    alpha.resize(circuit.getNrOfMultiplicationGates());
    random_for_inputs.resize(2 * circuit.getNrOfInputGates());

    if(fieldByteSize <= 4) {
        a_triple.resize(4* circuit.getNrOfMultiplicationGates());
        b_triple.resize(4* circuit.getNrOfMultiplicationGates());
        c_triple.resize(4* circuit.getNrOfMultiplicationGates());
        beta_triple.resize(2 * circuit.getNrOfMultiplicationGates());
    } else {
        a_triple.resize(2 * circuit.getNrOfMultiplicationGates());
        b_triple.resize(2 * circuit.getNrOfMultiplicationGates());
        c_triple.resize(2 * circuit.getNrOfMultiplicationGates());
        beta_triple.resize(circuit.getNrOfMultiplicationGates());
    }

    r_for_verify.resize(2* (16/field->getElementSizeInBytes() + 1)); // 16 bytes of aes key

    x_triple.resize(2* circuit.getNrOfMultiplicationGates());
    y_triple.resize(2* circuit.getNrOfMultiplicationGates());
    z_triple.resize(2* circuit.getNrOfMultiplicationGates());

}

template <class FieldType>
void ProtocolParty<FieldType>::generateRandomness31Bits() {

    vector<byte> sendBufsBytes_1;
    int numOfMult = circuit.getNrOfMultiplicationGates();
    SecretKey key;
    vector<byte> key_i_1(16);

    int numOfTriples = numOfMult;

    if(fieldByteSize <= 4) {
        numOfTriples = numOfMult*2;
    }

    vector<FieldType> alpha_for_triple(numOfTriples);

    PrgFromOpenSSLAES prg((numOfMult * 5 * fieldByteSize + numOfInputGates * fieldByteSize + 1)/32);
    PrgFromOpenSSLAES prg2((numOfMult * 5 * fieldByteSize + numOfInputGates * fieldByteSize + 1)/32);

    key = prg.generateKey(128);

    sendBufsBytes_1 = key.getEncoded();

    sendNext(sendBufsBytes_1,  key_i_1);

    SecretKey sk(key_i_1, "aes");

    prg2.setKey(sk); // ki-1

    prg.setKey(key); // ki

    for(int j=0; j<numOfMult;j++) {
        alpha[j] = field->GetElement(prg2.getRandom32()) - field->GetElement(prg.getRandom32());
    }

    for(int j=0; j<numOfTriples;j++) {
        alpha_for_triple[j] = field->GetElement(prg2.getRandom32()) - field->GetElement(prg.getRandom32());
    }

    // Generating Random Sharing For Inputs

    int numOfInputs = circuit.getNrOfInputGates();
    FieldType ri, riMinus1;

    for(int j=0; j < numOfInputs;j++) {
        ri = field->GetElement(prg.getRandom32());
        riMinus1 = field->GetElement(prg2.getRandom32());
        random_for_inputs[2*j] = riMinus1 - ri;
        random_for_inputs[2*j + 1] = num_0 - (num_2 * riMinus1) - ri;
    }

    // Generating Random Sharing For The Verification Stage

    int rounds =  (16/field->getElementSizeInBytes() + 1);
    for(int j=0; j < rounds;j++) {
        ri = field->GetElement(prg.getRandom32());
        riMinus1 = field->GetElement(prg2.getRandom32());
        r_for_verify[2*j] = riMinus1 - ri;
        r_for_verify[2*j + 1] = num_0 - (num_2 * riMinus1) - ri;
    }

    // Generating The Triples


    for(int j=0; j < numOfTriples; j++) {
        ri = field->GetElement(prg.getRandom32());
        riMinus1 = field->GetElement(prg2.getRandom32());
        a_triple[2*j] = riMinus1 - ri;
        a_triple[2*j + 1] = num_0 - (num_2 * riMinus1) - ri;
    }

    for(int j=0; j < numOfTriples; j++) {
        ri = field->GetElement(prg.getRandom32());
        riMinus1 = field->GetElement(prg2.getRandom32());
        b_triple[2*j] = riMinus1 - ri;
        b_triple[2*j + 1] = num_0 - (num_2 * riMinus1) - ri;
    }

    generateCForTriples(alpha_for_triple, numOfTriples);

}



template <class FieldType>
void ProtocolParty<FieldType>::generateRandomness61Bits() {

    vector<byte> sendBufsBytes_1;
    int numOfMult = circuit.getNrOfMultiplicationGates();
    SecretKey key;
    vector<byte> key_i_1(16);

    int numOfTriples = numOfMult;

    if(fieldByteSize <= 4) {
        numOfTriples = numOfMult*2;
    }

    vector<FieldType> alpha_for_triple(numOfTriples);

    PrgFromOpenSSLAES prg((numOfMult * 5 * fieldByteSize + numOfInputGates * fieldByteSize + 1)/32);
    PrgFromOpenSSLAES prg2((numOfMult * 5 * fieldByteSize + numOfInputGates * fieldByteSize + 1)/32);

    key = prg.generateKey(128);

    sendBufsBytes_1 = key.getEncoded();

    sendNext(sendBufsBytes_1,  key_i_1);

    SecretKey sk(key_i_1, "aes");

    prg2.setKey(sk); // ki-1

    prg.setKey(key); // ki

    for(int j=0; j<numOfMult;j++) {
        alpha[j] = field->GetElement(prg2.getRandom64()) - field->GetElement(prg.getRandom64());
    }

    for(int j=0; j<numOfTriples;j++) {
        alpha_for_triple[j] = field->GetElement(prg2.getRandom64()) - field->GetElement(prg.getRandom64());
    }

    // Generating Random Sharing For Inputs

    int numOfInputs = circuit.getNrOfInputGates();
    FieldType ri, riMinus1;

    for(int j=0; j < numOfInputs;j++) {
        ri = field->GetElement(prg.getRandom64());
        riMinus1 = field->GetElement(prg2.getRandom64());
        random_for_inputs[2*j] = riMinus1 - ri;
        random_for_inputs[2*j + 1] = num_0 - (num_2 * riMinus1) - ri;
    }

    // Generating Random Sharing For The Verification Stage

    int rounds =  (16/field->getElementSizeInBytes() + 1);
    for(int j=0; j < rounds;j++) {
        ri = field->GetElement(prg.getRandom64());
        riMinus1 = field->GetElement(prg2.getRandom64());
        r_for_verify[2*j] = riMinus1 - ri;
        r_for_verify[2*j + 1] = num_0 - (num_2 * riMinus1) - ri;
    }

    // Generating The Triples


    for(int j=0; j < numOfTriples; j++) {
        ri = field->GetElement(prg.getRandom64());
        riMinus1 = field->GetElement(prg2.getRandom64());
        a_triple[2*j] = riMinus1 - ri;
        a_triple[2*j + 1] = num_0 - (num_2 * riMinus1) - ri;
    }

    for(int j=0; j < numOfTriples; j++) {
        ri = field->GetElement(prg.getRandom64());
        riMinus1 = field->GetElement(prg2.getRandom64());
        b_triple[2*j] = riMinus1 - ri;
        b_triple[2*j + 1] = num_0 - (num_2 * riMinus1) - ri;
    }

    generateCForTriples(alpha_for_triple, numOfTriples);

}


template <class FieldType>
void ProtocolParty<FieldType>::generateCForTriples(vector<FieldType>& alpha_for_triple, int numOfMult) {

    FieldType p2, d2;
    FieldType ri, riMinus1;
    vector<FieldType> sendBufsElements(numOfMult);
    vector<byte> sendBufsBytes(numOfMult*field->getElementSizeInBytes());
    vector<byte> recBufsBytes(numOfMult*field->getElementSizeInBytes());

    for(int k = 0; k < numOfMult ; k++)
    {
        ri = (a_triple[(k * 2) + 1] * b_triple[(k * 2) + 1] -
              (a_triple[(k * 2)] * b_triple[(k * 2)]) + alpha_for_triple[k]) * inv_3;

        //send ri to pi+1 = RIGHT
        sendBufsElements[k] = ri;
    }

    //convert to bytes

    for(int j=0; j < numOfMult;j++) {
        field->elementToBytes(sendBufsBytes.data() + (j * fieldByteSize), sendBufsElements[j]);
    }

    sendNext(sendBufsBytes, recBufsBytes);

    int fieldBytesSize = field->getElementSizeInBytes();

    for(int k = 0; k < numOfMult; k++)
    {
        riMinus1 = field->bytesToElement(recBufsBytes.data() + (k * fieldBytesSize));

        ri = sendBufsElements[k];

        c_triple[k * 2] = riMinus1 - ri; // ei

        c_triple[k * 2 + 1] = num_0 - (num_2 * riMinus1) - ri; // fi
    }
}

template <class FieldType>
void ProtocolParty<FieldType>::verification(vector<FieldType>& x_triple, vector<FieldType>& y_triple, vector<FieldType>& z_triple,
                                           vector<FieldType>& a_triple, vector<FieldType>& b_triple, vector<FieldType>& c_triple, int numOfMult)
{
    int numOfRandomShares = 16/field->getElementSizeInBytes() + 1;

    PrgFromOpenSSLAES prg(numOfMult/4);

    vector <FieldType> row(numOfMult * 2);
    vector <FieldType> sigma(numOfMult * 2);
    vector <FieldType> s_row(numOfMult);
    vector <FieldType> s_sigma(numOfMult);
    vector <FieldType> hi(numOfMult * 2 + numOfRandomShares); // hi
    vector <FieldType> hiMinus1(numOfMult); // hi-1
    vector <FieldType> hiPlus1(numOfMult); // hi+1

    vector<byte> keyVector(16);

    keyVector = generateCommonKey(hi);
    // generating 128 bit AES key
    SecretKey sk(keyVector, "aes");
    prg.setKey(sk);

    // gcm initialization vector
    unsigned char iv1[] = {0xe0, 0xe0, 0x0f, 0x19, 0xfe, 0xd7, 0xba, 0x01,
                           0x36, 0xa7, 0x97, 0xf3};

    unsigned char iv2[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00};

    unsigned char iv3[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x01};

    unsigned char iv4[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x02};

    // generate random key for gcm "hashing", and add it to the "view" array:
    unsigned char *key = reinterpret_cast<unsigned char*>(keyVector.data());

    HashEncrypt hashObj1 = HashEncrypt(key, iv1, 12);
    HashEncrypt hashObj2 = HashEncrypt(key, iv2, 12);
    HashEncrypt hashObj3 = HashEncrypt(key, iv3, 12);
    HashEncrypt hashObj4 = HashEncrypt(key, iv4, 12);

    if(fieldByteSize > 4) {
        for(int j=0; j<numOfMult;j++) {

            beta_triple[j] = field->GetElement((prg.getRandom64() >> 3));
        }
    } else {
        for(int j=0; j<numOfMult;j++) {

            beta_triple[j] = field->GetElement(prg.getRandom32());
        }
    }

    int index = 0;
    for(int k = 0; k < circuit.getGates().size(); k++)
    {
        if (circuit.getGates()[k].gateType == MULT) {
            x_triple[index] = gateShareArr[2 * circuit.getGates()[k].input1];
            x_triple[index + 1] = gateShareArr[2 * circuit.getGates()[k].input1 + 1];
            y_triple[index] = gateShareArr[2 * circuit.getGates()[k].input2];
            y_triple[index + 1] = gateShareArr[2 * circuit.getGates()[k].input2 + 1];
            z_triple[index] = gateShareArr[2 * circuit.getGates()[k].output];
            z_triple[index + 1] = gateShareArr[2 * circuit.getGates()[k].output + 1];
            index+=2;
        }
    }

    // The parties run the protocol 7.4

    int end = y_triple.size();

    for(int j=0; j<numOfMult;j++) {

        row[2*j] = x_triple[2*j] *  beta_triple[j] + a_triple[2*j];
        row[2*j + 1] = x_triple[2*j + 1] *  beta_triple[j] + a_triple[2*j + 1];

        sigma[2*j] = y_triple[2*j] + b_triple[2*j];
        sigma[2*j + 1] = y_triple[2*j + 1] + b_triple[2*j + 1];
    }

    index = 0;
    for(int j=numOfMult*2; j<end;j++) {

        row[2*j] = x_triple[2*index] * beta_triple[j] + a_triple[2*j];
        row[2*j + 1] = x_triple[2*index + 1] * beta_triple[j] + a_triple[2*j + 1];

        sigma[2*j] = y_triple[2*index] + b_triple[2*j];
        sigma[2*j + 1] = y_triple[2*index + 1] + b_triple[2*j + 1];

        index++;
    }

    // run open(row) and open(sigma)
    openShare(numOfMult, row, s_row);
    openShare(numOfMult, sigma, s_sigma);

   // index = 0;
    for(int i=0; i<numOfMult; i++) {
        hi[numOfRandomShares + 2*i] = s_row[i];
        hi[numOfRandomShares + 2*i + 1] = s_sigma[i];
    }


    // each party pi computes locally the share of v
    // ti, si is the shares of v
    for(int i=0; i < numOfMult; i++) {

        hiPlus1[i] = z_triple[2*i] * beta_triple[i] - c_triple[2*i] + s_sigma[i] * a_triple[2*i] + s_row[i] * b_triple[2*i]; // ti
        hiMinus1[i] = z_triple[2*i + 1] * beta_triple[i] - c_triple[2*i + 1] + s_sigma[i] * a_triple[2*i + 1] + s_row[i] * b_triple[2*i + 1] - (num_0 - (s_sigma[i] * s_row[i])); // si

    }

    index = 0;
    for(int i=numOfMult*2; i < end; i++) {

        hiPlus1[i] = z_triple[2*index] * beta_triple[i] - c_triple[2*i] + s_sigma[i] *  a_triple[2*i] + s_row[i] *  b_triple[2*i]; // ti
        hiMinus1[i] = z_triple[2*index + 1] * beta_triple[i] - c_triple[2*i + 1] + s_sigma[i] *  a_triple[2*i + 1] + s_row[i] * b_triple[2*i + 1] - (num_0 - (s_sigma[i] * s_row[i])); // si
        index++;

    }

    // comparing views
    comparingViews(hi, hiPlus1, hiMinus1, numOfMult, hashObj1, hashObj2, hashObj3, hashObj4);

}

template <class FieldType>
void ProtocolParty<FieldType>::comparingViews(vector<FieldType>& hi,vector<FieldType>& hiPlus1,vector<FieldType>& hiMinus1, int NrOfMultiplicationGates,
                                         HashEncrypt& hashObj1, HashEncrypt& hashObj2, HashEncrypt& hashObj3, HashEncrypt& hashObj4)
{

    int sizeOfHi = hi.size();
    int sizeOfHiPlus1 = hiPlus1.size();

    vector<byte> recBufBytes(32);
    vector<byte> sendBuf;
    vector<byte> sendBufHiPlus1;
    vector<byte> hashedViewsForSendBytes(32);

    sendBuf.resize((sizeOfHi)*fieldByteSize);
    sendBufHiPlus1.resize((sizeOfHiPlus1)*fieldByteSize);


    for(int j=0; j < sizeOfHi; j++) {

        field->elementToBytes(sendBuf.data() + (j* fieldByteSize), hi[j]);
    }

    for(int j=0; j < sizeOfHiPlus1; j++) {

        field->elementToBytes(sendBufHiPlus1.data() + (j * fieldByteSize), hiPlus1[j]);
    }

    unsigned int hashSize = 16;
    unsigned char hashedViewsForSend[hashSize*2]; // HASH-SIZE
    unsigned char hashedViewsForCompare[hashSize];


    hashObj1.getHashedDataOnce(reinterpret_cast<unsigned char*> (sendBuf.data()), sizeOfHi, hashedViewsForSend, &hashSize); // di = HASH(hi)

    if (m_partyId == 0) {
        hashObj4.getHashedDataOnce(reinterpret_cast<unsigned char *> (hiPlus1.data()), sizeOfHiPlus1,
                                   &(hashedViewsForSend[16]), &hashSize); // di+1 = HASH_4(hi+1)

        hashObj2.getHashedDataOnce(reinterpret_cast<unsigned char*> (hiMinus1.data()), sizeOfHiPlus1,
                                   hashedViewsForCompare, &hashSize); // di-1 = HASH_2(hi-1)
    }

    if (m_partyId == 1) {
        hashObj3.getHashedDataOnce(reinterpret_cast<unsigned char *> (hiPlus1.data()), sizeOfHiPlus1,
                                   &(hashedViewsForSend[16]), &hashSize); // di+1 = HASH_3(hi+1)

        hashObj4.getHashedDataOnce(reinterpret_cast<unsigned char*> (hiMinus1.data()), sizeOfHiPlus1,
                                   hashedViewsForCompare, &hashSize); // di-1 = HASH_4(hi-1)
    }

    if (m_partyId == 2) {
        hashObj2.getHashedDataOnce(reinterpret_cast<unsigned char *> (hiPlus1.data()), sizeOfHiPlus1,
                                   &(hashedViewsForSend[16]), &hashSize); // di+1 = HASH_2(hi+1)

        hashObj3.getHashedDataOnce(reinterpret_cast<unsigned char*> (hiMinus1.data()), sizeOfHiPlus1,
                                   hashedViewsForCompare, &hashSize); // di-1 = HASH_3(hi-1)
    }

    for(int j=0; j < 32; j++) {
        hashedViewsForSendBytes[j] = hashedViewsForSend[j];
    }

    sendNext(hashedViewsForSendBytes, recBufBytes);

    // check the result

    bool flag = true;

    for(int j = 0; j < 16;j++) {
        if (recBufBytes[j] !=  hashedViewsForSend[j]) {
            cout << "cheating hi" << endl;
            flag = false;
        }
    }

    for(int j = 16; j< 32;j++) {
      if (recBufBytes[j] !=  hashedViewsForCompare[j - 16]) {
          cout << "cheating hi-1" << endl;
          flag = false;
      }
    }

    if(flag) {
        cout << "no cheating" << endl;
    }

}

template <class FieldType>
void ProtocolParty<FieldType>::inputPreparation()
{
    int robin = 0;
    // the number of random double sharings we need altogether
    vector<FieldType> x1(N),y1(N);
    vector<vector<FieldType>> sendBufsElements(N);
    vector<vector<byte>> sendBufsBytes(N);
    vector<vector<byte>> recBufBytes(N);
    vector<vector<FieldType>> recBufElements(N);

    int input;
    int index = 0;
    vector<int> sizes(N);
    FieldType s1,s2,s3,t1,t2,t3, r1,r2,r3;

    // prepare the shares for the inputs
    for (int k = 0; k < numOfInputGates; k++)
    {
        if(circuit.getGates()[k].gateType == INPUT) {
            //get the expected sized from the other parties
            sizes[(circuit.getGates()[k].party)]++;  // MEITAL

            // send to party (which need this gate) your share for this gate
            sendBufsElements[circuit.getGates()[k].party].push_back(random_for_inputs[2*k]);// send t
        }
    }

    for(int i=0; i < N; i++)
    {

        sendBufsBytes[i].resize(sendBufsElements[i].size()*fieldByteSize);
        recBufBytes[i].resize(sizes[m_partyId]*fieldByteSize);
        for(int j=0; j<sendBufsElements[i].size();j++) {
            field->elementToBytes(sendBufsBytes[i].data() + (j * fieldByteSize), sendBufsElements[i][j]);
        }
    }

    roundFunctionSync(sendBufsBytes, recBufBytes,10);


    //turn the bytes to elements
    for(int i=0; i < N; i++)
    {
        recBufElements[i].resize(((recBufBytes[i].size()) / fieldByteSize));
        for(int j=0; j<recBufElements[i].size();j++) {
            recBufElements[i][j] = field->bytesToElement(recBufBytes[i].data() + ( j * fieldByteSize));
        }
    }

    vector<int> counters(N);

    for(int i=0; i<N; i++){
        counters[i] =0;
    }

    int counter = 0;
    FieldType t_i_1, ti, m_t, m_s;

    vector<vector<FieldType>> sendBufsElements_1(N);
    vector<vector<byte>> sendBufsBytes_1(N);
    vector<vector<byte>> recBufBytes_1(N);
    vector<vector<FieldType>> recBufElements_1(N);

    index = 0;
    vector<int> sizes_1(N);
    for(int i=0; i<N; i++){
        sizes_1[i] = 0;
    }

     //  The parties run reconstruct
    for (int k = 0; k < numOfInputGates; k++)
    {
        if(circuit.getGates()[k].gateType == INPUT && circuit.getGates()[k].party == m_partyId)
        {
            t_i_1 = field->bytesToElement(recBufBytes[LEFT].data() + (counter*fieldByteSize));
            ti = field->bytesToElement(recBufBytes[RIGHT].data() + ((counter)*fieldByteSize));

            m_t = random_for_inputs[k*2];
            m_s = random_for_inputs[k*2 + 1];
            FieldType value = t_i_1 + ti + m_t;
            // my output: reconstruct received shares
            if (value != *field->GetZero())
            {
                // someone cheated!
                cout << "cheating!!!" << '\n';

                return;
            }

            FieldType v = t_i_1 - m_s; // holding r

            auto input = myInputs[index];
            index++;

            sendBufsElements_1[LEFT].push_back(field->GetElement(input) - v);
            sendBufsElements_1[RIGHT].push_back(field->GetElement(input) - v);

            counter++;

            gateShareArr[2*(circuit.getGates()[k].output)] = m_t;// set the share sent from the party owning the input
            gateShareArr[2*(circuit.getGates()[k].output)+1] = m_s - (field->GetElement(input) - v);

        }
        sizes_1[circuit.getGates()[k].party]++;
    }

    for(int i=0; i < N; i++)
    {
        sendBufsBytes_1[i].resize(sendBufsElements_1[i].size()*fieldByteSize);
        recBufBytes_1[i].resize(sizes_1[i]*fieldByteSize); // MEITAL!!
        for(int j=0; j<sendBufsElements_1[i].size();j++) {
            field->elementToBytes(sendBufsBytes_1[i].data() + (j * fieldByteSize), sendBufsElements_1[i][j]);
        }
    }

    roundFunctionSync(sendBufsBytes_1, recBufBytes_1,11);

    //turn the bytes to elements
    for(int i=0; i < N; i++)
    {
        recBufElements_1[i].resize(((recBufBytes_1[i].size()) / fieldByteSize));
        for(int j=0; j<recBufElements_1[i].size();j++) {
            recBufElements_1[i][j] = field->bytesToElement(recBufBytes_1[i].data() + ( j * fieldByteSize));
        }
    }

    vector<int> counters_1(N);

    for(int i=0; i<N; i++){
        counters_1[i] = 0;
    }

    //every party compute locally the shares of inputs

    for (int k = 0; k < numOfInputGates; k++) {
        if (circuit.getGates()[k].gateType == INPUT && circuit.getGates()[k].party != m_partyId) {
            gateShareArr[2*(circuit.getGates()[k].output)] = random_for_inputs[2*k];// set the share sent from the party owning the input
            gateShareArr[2*(circuit.getGates()[k].output)+1] = random_for_inputs[2*k + 1] -
                    recBufElements_1[circuit.getGates()[k].party][counters_1[circuit.getGates()[k].party]];
            counters_1[circuit.getGates()[k].party] += 1;
        }
    }

}

template <class FieldType>
void ProtocolParty<FieldType>::openShare(int numOfRandomShares, vector<FieldType> &shares, vector<FieldType> &secrets){

    int robin = 0;

    vector<vector<FieldType>> sendBufsElements(N);
    vector<vector<byte>> sendBufsBytes(N);
    vector<vector<byte>> recBufBytes(N);
    vector<vector<FieldType>> recBufElements(N);

    int input;
    int index = 0;
    FieldType s1,s2,s3,t1,t2,t3, r1,r2,r3;

    for (int k = 0; k < numOfRandomShares; k++)
    {
        sendBufsElements[RIGHT].push_back(shares[2*k]);// t
    }

    int fieldByteSize = field->getElementSizeInBytes();

    for(int i=0; i < N; i++)
    {
        sendBufsBytes[i].resize(sendBufsElements[i].size()*fieldByteSize);

        for(int j=0; j<sendBufsElements[i].size();j++) {
            field->elementToBytes(sendBufsBytes[i].data() + (j * fieldByteSize), sendBufsElements[i][j]);
        }
    }

    recBufBytes[LEFT].resize(numOfRandomShares*fieldByteSize);
    recBufBytes[RIGHT].resize(0);
    recBufBytes[m_partyId].resize(numOfRandomShares*fieldByteSize);

    roundFunctionSync(sendBufsBytes, recBufBytes,10);


    //turn the bytes to elements
    for(int i=0; i < N; i++)
    {
        recBufElements[i].resize(((recBufBytes[i].size()) / fieldByteSize));
        for(int j=0; j<recBufElements[i].size();j++) {
            recBufElements[i][j] = field->bytesToElement(recBufBytes[i].data() + ( j * fieldByteSize));
        }
    }

    int counter = 0;
    FieldType t_i_1, ti, m_t, m_s;

    vector<vector<FieldType>> sendBufsElements_1(N);
    vector<vector<byte>> sendBufsBytes_1(N);
    vector<vector<byte>> recBufBytes_1(N);
    vector<vector<FieldType>> recBufElements_1(N);

    index = 0;
    vector<int> sizes_1(N);
    for(int i=0; i<N; i++){
        sizes_1[i] = 0;
    }

    //  The parties run reconstruct

    for (int k = 0; k < numOfRandomShares; k++) {
        t_i_1 = field->bytesToElement(recBufBytes[LEFT].data() + (counter * fieldByteSize));

        m_s = shares[k * 2 + 1];

        FieldType v = t_i_1 - m_s; // holding r

        secrets[k] = v;

        counter++;
    }
}

template <class FieldType>
vector<byte> ProtocolParty<FieldType>::generateCommonKey(vector<FieldType>& aesArray){

    //calc the number of elements needed for 128 bit AES key
   int numOfRandomShares = 16/field->getElementSizeInBytes() + 1;

   // vector<FieldType> aesArray(numOfRandomShares);
    vector<byte> aesKey(numOfRandomShares*fieldByteSize);

    //generate enough random shares for the AES key
    openShare(numOfRandomShares, r_for_verify, aesArray);

    //turn the aes array into bytes to get the common aes key.
    for(int i=0; i<numOfRandomShares;i++){

        for(int j=0; j<numOfRandomShares;j++) {
            field->elementToBytes(aesKey.data() + (j * fieldByteSize), aesArray[j]);
        }
    }

    //reduce the size of the key to 16 bytes
    aesKey.resize(16);

    return aesKey;

}


template <class FieldType>
void ProtocolParty<FieldType>::computationPhase() {

    currentCirciutLayer = 0;
    mult_count = 0;

    int count = 0, num;
    int c_currentCirciutLayer, c_nextCirciutLayer;

    int numOfLayers = circuit.getLayers().size();
    for(int i=0; i<numOfLayers-1;i++){

        currentCirciutLayer = i;
        count = processNotMult();

        c_currentCirciutLayer = circuit.getLayers()[currentCirciutLayer];
        c_nextCirciutLayer =  circuit.getLayers()[currentCirciutLayer+1];

        count += processMultiplications();
    }
}


template <class FieldType>
int ProtocolParty<FieldType>::processNotMult(){
    int count=0;
    for(int k=circuit.getLayers()[currentCirciutLayer]; k < circuit.getLayers()[currentCirciutLayer+1]; k++)
    {
        // add gate
        if(circuit.getGates()[k].gateType == ADD)
        {
            gateShareArr[circuit.getGates()[k].output * 2] = gateShareArr[circuit.getGates()[k].input1 * 2] + gateShareArr[circuit.getGates()[k].input2 * 2]; // t+t
            gateShareArr[(circuit.getGates()[k].output * 2) + 1] = gateShareArr[(circuit.getGates()[k].input1 * 2) + 1] + gateShareArr[(circuit.getGates()[k].input2 * 2) + 1]; // s+s
            count++;
        }
        else if(circuit.getGates()[k].gateType == SCALAR)
        {
            long scalar(circuit.getGates()[k].input2);
            FieldType e = field->GetElement(scalar);

            gateShareArr[circuit.getGates()[k].output * 2] = gateShareArr[circuit.getGates()[k].input1 * 2]; // t
            gateShareArr[(circuit.getGates()[k].output * 2) + 1] = gateShareArr[(circuit.getGates()[k].input1 * 2) + 1] * e; // s*e

            count++;
        }
        else if(circuit.getGates()[k].gateType == SCALAR_ADD)
        {
            long scalar(circuit.getGates()[k].input2);
            FieldType e = field->GetElement(scalar);

            gateShareArr[circuit.getGates()[k].output * 2] = gateShareArr[circuit.getGates()[k].input1 * 2]; // t
            gateShareArr[(circuit.getGates()[k].output * 2) + 1] = gateShareArr[(circuit.getGates()[k].input1 * 2) + 1] - e; // s-e

            count++;
        }
    }

    return count;

}

/**
 * the Function process all multiplications which are ready.
 * @return the number of processed gates.
 */
template <class FieldType>
int ProtocolParty<FieldType>::processMultiplications()
{
    int last = circuit.getLayers()[currentCirciutLayer+1];
    int first = circuit.getLayers()[currentCirciutLayer];
    int size = (last - first);
    int index = 0;
    FieldType p2, d2;
    FieldType ri, r_i_1;
    vector<FieldType> sendBufsElements(size);
    vector<byte> sendBufsBytes(size*fieldByteSize);
    vector<byte> recBufsBytes(size*fieldByteSize);

    for(int k = circuit.getLayers()[currentCirciutLayer]; k < circuit.getLayers()[currentCirciutLayer+1] ; k++)//go over only the logit gates
    {
        // its a multiplication which not yet processed and ready
        if(circuit.getGates()[k].gateType == MULT)
        {

            ri = (gateShareArr[(circuit.getGates()[k].input1 * 2) + 1] * gateShareArr[(circuit.getGates()[k].input2 * 2) + 1] -
                    gateShareArr[(circuit.getGates()[k].input1 * 2)] * gateShareArr[(circuit.getGates()[k].input2 * 2)] + alpha[mult_count]) * inv_3;

            //send ri to pi+1 = RIGHT
            sendBufsElements[index] = ri;

            index++;
            mult_count++;
        }
    }

    //convert to bytes
    for(int j=0; j < size; j++) {
        field->elementToBytes(sendBufsBytes.data() + (j * fieldByteSize), sendBufsElements[j]);
    }

    sendNext(sendBufsBytes, recBufsBytes);

    index = 0;

    for(int k = first; k < last; k++) {

        if(circuit.getGates()[k].gateType == MULT) {

                r_i_1 = field->bytesToElement(recBufsBytes.data() + (index * fieldByteSize));

                ri = sendBufsElements[index];

                gateShareArr[(circuit.getGates()[k].output) * 2] = r_i_1 - ri; // ei

                gateShareArr[(circuit.getGates()[k].output) * 2 + 1] = num_0 - (num_2 * r_i_1) - ri; //  fi


            index++;
        }

    }


    return index;
}

/**
 * the function Walk through the circuit and reconstruct output gates.
 * @param circuit
 * @param gateShareArr
 * @param alpha
 */
template <class FieldType>
void ProtocolParty<FieldType>::outputPhase()
{
    int count=0;
    vector<FieldType> x1(N); // vector for the shares of my outputs
    vector<vector<FieldType>> sendBufsElements(N);
    vector<vector<byte>> sendBufsBytes(N);
    vector<vector<byte>> recBufBytes(N);

    FieldType num;
    ofstream myfile;
    myfile.open(outputFile);

    for(int k=M-numOfOutputGates; k < M; k++)
    {
        if(circuit.getGates()[k].gateType == OUTPUT)
        {
            // send to party (which need this gate) your share for this gate
            sendBufsElements[circuit.getGates()[k].party].push_back(gateShareArr[2*circuit.getGates()[k].input1]);// send t
        }
    }

    for(int i=0; i < N; i++)
    {
        sendBufsBytes[i].resize(sendBufsElements[i].size()*fieldByteSize);
        recBufBytes[i].resize(sendBufsElements[m_partyId].size()*fieldByteSize);
        for(int j=0; j<sendBufsElements[i].size();j++) {
            field->elementToBytes(sendBufsBytes[i].data() + (j * fieldByteSize), sendBufsElements[i][j]);
        }
    }

    roundFunctionSync(sendBufsBytes, recBufBytes,7);

    FieldType t_i_1, ti, m_t, m_s;
    int counter = 0;

    for(int k=M-numOfOutputGates ; k < M; k++) {
        if(circuit.getGates()[k].gateType == OUTPUT && circuit.getGates()[k].party == m_partyId)
        {

            t_i_1 = field->bytesToElement(recBufBytes[LEFT].data() + (counter*fieldByteSize));
            ti = field->bytesToElement(recBufBytes[RIGHT].data() + ((counter)*fieldByteSize));

            m_t = gateShareArr[(circuit.getGates()[k].input1)*2];
            m_s = gateShareArr[(circuit.getGates()[k].input1)*2 + 1];
            FieldType value = t_i_1 + ti + m_t;

            // my output: reconstruct received shares
            if (value != *field->GetZero())
            {
                // someone cheated!
                cout << "cheating!!!" << '\n';

                return;
            }

            FieldType v = t_i_1 - m_s;
            cout << "the result for "<< circuit.getGates()[k].input1 << " is : " << field->elementToString(t_i_1 - m_s) << '\n';

            counter++;
        }
    }

    // close output file
    myfile.close();
}

/**
 * communication
 * @tparam FieldType
 * @param sendBufs
 * @param recBufs
 * @param round
 */
template <class FieldType>
void ProtocolParty<FieldType>::roundFunctionSync(vector<vector<byte>> &sendBufs, vector<vector<byte>> &recBufs, int round) {

    int numThreads = 2;
    int numPartiesForEachThread = 1;

    recBufs[m_partyId] = sendBufs[m_partyId];
    //recieve the data using threads
    vector<thread> threads(numThreads);
    for (int t=0; t<numThreads; t++) {
        if ((t + 1) * numPartiesForEachThread <= parties.size()) {
            threads[t] = thread(&ProtocolParty::exchangeData, this, ref(sendBufs), ref(recBufs),
                                t * numPartiesForEachThread, (t + 1) * numPartiesForEachThread);
        } else {
            threads[t] = thread(&ProtocolParty::exchangeData, this, ref(sendBufs), ref(recBufs), t * numPartiesForEachThread, parties.size());
        }
    }
    for (int t=0; t<numThreads; t++){
        threads[t].join();
    }

}

template <class FieldType>
void ProtocolParty<FieldType>::sendNext(vector<byte> &sendBufs, vector<byte> &recBufs) {

    if (m_partyId == 0)
    {
        rightChannel->write(sendBufs.data(), sendBufs.size()); // write to party 2

        leftChannel->read(recBufs.data(), recBufs.size()); // read from party 3

    } else if (m_partyId == 1)
    {
        leftChannel->read(recBufs.data(), recBufs.size()); // read from party 1

        rightChannel->write(sendBufs.data(), sendBufs.size()); // write to party 3

    } else {

        rightChannel->write(sendBufs.data(), sendBufs.size()); // write to party 1

        leftChannel->read(recBufs.data(), recBufs.size()); // read from party 2
    }

}

template <class FieldType>
void ProtocolParty<FieldType>::exchangeData(vector<vector<byte>> &sendBufs, vector<vector<byte>> &recBufs, int first, int last){

    //cout<<"in exchangeData";
    for (int i=first; i < last; i++) {

        if ((m_partyId) < parties[i]->getID()) {

            //send shares to my input bits
            parties[i]->getChannel()->write(sendBufs[parties[i]->getID()].data(), sendBufs[parties[i]->getID()].size());
            //cout<<"write the data:: my Id = " << m_partyId - 1<< "other ID = "<< parties[i]->getID() <<endl;

            //receive shares from the other party and set them in the shares array
            parties[i]->getChannel()->read(recBufs[parties[i]->getID()].data(), recBufs[parties[i]->getID()].size());
            //cout<<"read the data:: my Id = " << m_partyId-1<< "other ID = "<< parties[i]->getID()<<endl;

        } else{
            //receive shares from the other party and set them in the shares array
            parties[i]->getChannel()->read(recBufs[parties[i]->getID()].data(), recBufs[parties[i]->getID()].size());
            //cout<<"read the data:: my Id = " << m_partyId-1<< "other ID = "<< parties[i]->getID()<<endl;

            //send shares to my input bits
            parties[i]->getChannel()->write(sendBufs[parties[i]->getID()].data(), sendBufs[parties[i]->getID()].size());
            //cout<<"write the data:: my Id = " << m_partyId-1<< "other ID = "<< parties[i]->getID() <<endl;

        }
    }
}


template <class FieldType>
ProtocolParty<FieldType>::~ProtocolParty()
{
    delete field;
    delete timer;
    //delete comm;
}

#endif /* PROTOCOL_H_ */
