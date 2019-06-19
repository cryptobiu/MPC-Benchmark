#pragma once

#include <cmath>
#include <NTL/ZZ_p.h>

#include <libscapi/include/primitives/Prg.hpp>
#include <libscapi/include/cryptoInfra/Protocol.hpp>

#include "TinyOT.hpp"
#include "Utils.hpp"
#include "Circuit.hpp"

#include "libOTe/Tools/Tools.h"
#include "libOTe/Tools/LinearCode.h"

using namespace NTL;

/**
 * This class represents a party in the Low cost constant round MPC combining BMR and ot protocol.
 */
class Party : public MPCProtocol, DisHonestMajority{

private:
    int id;                         //Each party gets unique id number
    u_int32_t numParties;           //Number of parties in the protocol

    int numThreads;                 //Number of threads to use in the protocol.
                                    //Usually this will be (#parties - 1) or (#parties - 1)*2
    Circuit circuit;               //The circuit the protocol computes
    bitVector inputs;
    bitVector outputs;

    int times, iteration; //Number of times to run the protocol

    ofstream outputFile;           //The file where the protocol times are written to.

    Utils utils;                    //Utility class that perform some of the protocol functionalities, such as broadcast
    TinyOT tinyOT;                  //The tinyOT instance that perform the tiny ot operation of the protocol

    boost::asio::io_service io_service;      //Used in scapi communication
    osuCrypto::IOService ios_ot;             //used in LibOTe communication
    vector<ProtocolPartyData*> parties;      //The communication data.

    Measurement* measurement;
    PrgFromOpenSSLAES prg;                   //Used in the protocol in order to get random bytes
    EVP_CIPHER_CTX* aes;                     //Used in the protocol in order to encrypt data
    const EVP_CIPHER* cipher;

    //The following vectors contain the sharings of all the circuit wires.
    //They are held twice - once in the wires format in order to give an easy way to get the sharings.
    //There are cases where the same sharing is shared between multiple wires, so, in order to delete them without
    // memory corruption, we keep the other sharing vectors where there are no duplications.
    vector<Sharing*> allWiresSharings;
    block* xorMemory;   //memory of the sharings. we keep this in order to delete all the sharings memory at once.
    vector<Sharing*> sharings, xorSharings;

    block* allWiresKeys;                    //K0 of all wires
    block* gatesEntries;                    //Garbled tables of all gates
    vector<byte> allLambdaInputs;           //Lambda values of the inputs wires of this party
    vector<byte> allLambdaOutputs;          //Lambda values of the outputs wires
    block R;                                //The R value that unique for this party.

    /**
     * Passing through the wires of the circuit topologically, proceed as follows:
     *  • If w is a circuit-input wire, or the output of an AND gate:
     *      (a) Generate a random wire mask [λ w ] using the Bits command of Π n-TinyOT.
     *      (b) Every P i samples a key k w,0 ← {0, 1} κ and sets k w,1 = k w,0 ⊕ R i.
     *  • If the wire w is the output of a XOR gate:
     *      (a) The parties compute the mask on the output wire as [λ w ] = [λ u ] + [λ v ].
     *      (b) Every P i sets k w,0 = k u,0 ⊕ k v,0 and k w,1 = k w,0 ⊕ R i.
     * @param tinyOT used to call bits function
     * @param sharings the vector that bits function fill
     * @param allWiresSharings the vector that should be filled during this function. Each wire gets a sharings.
     */
    void generateMasksAndKeys(TinyOT* tinyOT, vector<Sharing*> & sharings, vector<Sharing*> & allWiresSharings);

    /**
     * (a) For each AND gate g ∈ G, the parties compute hλ uv i = hλ u i · hλ v i by calling Multiply on
     *      F n-TinyOT.
     * (b) For each AND gate g, party P i can compute an additive share of the 3n values:
     *      λ u · R j, λ v · R j, λ uvw · R j,   for j ∈ [n]
     *      where λ uvw := λ uv + λ w .
     *    Each P i then uses these to compute, for a, b ∈ {0, 1} 2 a share of:
     *      ρ j,a,b = λ u · R j ⊕ a · λ v · R j ⊕ b · λ uvw · R j ⊕ a · b · R j
     * @param tinyOT used to call multiply function
     * @param allWiresSharings contains the sharings of all the circuit's wires.
     */
    void secureProductComputation(TinyOT* tinyOT, vector<Sharing*> & allWiresSharings);

    /**
     * For each AND gate g ∈ G, each j ∈ [n], and the four combinations of a, b ∈ {0, 1} 2, the parties compute shares
     * of the j-th entry of the garbled gate g̃ a,b as follows:
     * • P j sets (g̃ a,b)^j = ρa,b^j ⊕ F ku,a,kv,b (g||j) ⊕ k w,0.
     * • For every i != j, Pi sets j(g̃ a,b) = ρ a,b^i ⊕ F k u,a,kv,b(g||j)
     */
    void garble();

    /**
     * For every circuit-output-wire w, the parties run Π Open to reveal λw to all the parties.
     * @param tinyOT used to call open
     * @param allWiresSharings contains the sharings of all the circuit's wires.
     */
    void revealOutputs(TinyOT* tinyOT, vector<Sharing*> & allWiresSharings);

    /**
     * For every circuit input wire w corresponding to party Pi’s input, the parties run Πi Open to open λw to Pi.
     * @param tinyOT used to call open
     * @param allWiresSharings contains the sharings of all the circuit's wires.
     */
    void revealInputs(TinyOT* tinyOT, vector<Sharing*> & allWiresSharings);

    /**
     * Let C̃ i = ((g̃ a,b) i ) j,a,b,g ∈ {0, 1}^ 4nκ|G| be Pi ’s share of the whole garbled circuit.
     * 4. Each party P i sends C̃ i to all other parties.
     * 5. Each party reconstructs the garbled circuit by XORing the shares together.
     */
    void openGarble();

    /**
     * For all input wires w with input from Pi, party Pi computes Λw = ρ w ⊕ λw, where ρw is Pi ’s input to Cf,
     * and λw was obtained in the preprocessing stage.
     * Then, Pi broadcasts the public value Λ w to all parties.
     * For all input wires w, each party P i broadcasts the key k w associated to Λ w .
     * @param inputs input values for of this party
     * @param computeKeys all k0 shares of all the wires.
     * @param publicValues will contain the public values of all the circuit's wires.
     */
    void sendGarblesLabels(const bitVector & inputs, block* computeKeys, const bitVector & publicValues);

    /**
     * Passing through the circuit topologically, the parties can now locally compute the following operations for
     * each gate g. Let the gates input wires be labelled u and v, and the output wire be labelled w. Let a and b be
     * the respective public values on the input wires.
     * 1. If g is a XOR gate, set the public value on the output wire to be c = a + b.
     *                        In addition, for every j ∈ [n], each party computes k w,c = k u,a ⊕ k v,b.
     * 2. If g is an AND gate , then each party computes, for all j ∈ [n]:
     *                        kw,c = g̃ a,b ⊕ (⊕i = 1,... , n F ku,a kv,b(g||j))
     * 3. If kw,c !∈ { kw,0, kw,0⊕ R }, then Pi outputs abort.
     * Otherwise, it proceeds. If Pi aborts it notifies all other parties with that information.
     * If Pi is notified that another party has aborted it aborts as well.
     * 4. If k w,c = k w,0 then Pi sets c = 0; if k w,c= k w,1 then Pi sets c = 1.
     * 5. The output of the gate is defined to be (k 1, w,c , . . . , k n, w,c) and the public value c.
     * @param computeKeys all k0 shares of all the wires.
     * @param publicValues will contain the public values of all the circuit's wires.
     */
    void localComputeCircuit(block* computeKeys, const bitVector & publicValues);

    /**
     * Assuming no party aborts, everyone will obtain a public value cw for every circuit-output wire w. The party
     * can then recover the actual output value from ρ w = c w ⊕ λ w , where λw was obtained in the preprocessing
     * stage.
     * @param computeKeys all k0 shares of all the wires.
     * @param publicValues will contain the public values of all the circuit's wires.
     * @return the circuit output
     */
    bitVector computeOutput(block* computeKeys, const bitVector & publicValues);

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
    Party(int argc, char* argv[]);//int id, Circuit* circuit, string partiesFile, int numThreads, ofstream * outputFile, int B);

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
    bitVector compute();

    /**
     * Reads the inputs form the input file
     * @param inputFileName contains the input of this party.
     * @return the inputs of this party
     */
    bitVector readInputs(string inputFileName);

    bitVector getOutput(){
        return outputs;
    }

    /**
     * Initialize the times in order make all the parties ready for the next computation.
     * This will make sure no party will wait until the others will start computation.
     */
    void initTimes();

};
