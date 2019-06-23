//
// Created by moriya on 15/2/17.
//

#ifndef LIBSCAPI_YAOSEPARTY_H
#define LIBSCAPI_YAOSEPARTY_H

#include <libscapi/include/cryptoInfra/Protocol.hpp>
#include <libscapi/include/cryptoInfra/SecurityLevel.hpp>
#include </usr/local/include/emp-tool/utils/block.h>
#include <EMP/emp-m2pc/malicious/malicious.h>
#include <libscapi/tools/circuits/scapiBristolConverter/CircuitConverter.hpp>
#include <libscapi/include/infra/ConfigFile.hpp>
#include <libscapi/include/infra/Measurement.hpp>
#include <fstream>

using namespace emp;
typedef unsigned char byte;

extern CircuitFile *cf;
extern void compute(Bit * res, Bit * in, Bit * in2);

/**
 * This class represents the Yao single execution protocol.
 * It wraps the protocol implemented by EMP (Efficient Multi-Party computation toolkit, and the implementation can be
 * found at https://github.com/emp-toolkit/emp-m2pc.
 *
 * The protocol has two modes:
 * 1. Run the protocol at once - this is done by running the run function.
 * 2. Run the protocol with offline-online phases - this is done by calling the runOffline(), preOnline() and then
 * runOnline() functions. In order to synchronize between the parties between the different phases, there is also a sync()
 * function.
 *
 */
class YaoSEParty : public MPCProtocol, public Malicious {
private:
    int id;             // The party id
    bool * input;       // inputs for this party
    NetIO *io;          //The communication object
    bool* out;          //The protocol output
    Malicious2PC <NetIO, RTCktOpt::off> * mal; // The underlying object
    int times, currentIteration;
    /*
	 * Reads the input from the given file.
	 */
    void readInputs(string inputFile, bool * inputs, int size);



public:
    /**
     * Constructor that sets the given parameters.
     * @param id party id
     * @param circuitFile file contains the circuit
     * @param ip ip of the first party (server)
     * @param port port of the first party
     * @param inputFile file contains the inputs for this party
     */
    YaoSEParty(int argc, char* argv[]);

    ~YaoSEParty(){
        delete cf;
        delete timer;
    }

    bool hasOffline() override { return true; }
    bool hasOnline() override { return true; }

    /*
     * Implement the function derived from the Protocol abstract class.
     * Runs the protocol at once (not in the offline- online mode)
     */
    void run() override;

    /**
     * Synchronize the parties to be able to run the protocol without waiting.
     */
    void sync();

    /**
     * In case the user wants to execute the protocol using the offline and online functions, he has to set the iteration number himself.
     * @param iteration
     */
    void setIteration(int iteration){ currentIteration = iteration; }

    /**
     * Execute the offline phase of the protocol.
     */
    void runOffline() override;

    /**
     * Load from the disk the output of the offline phase, in order use it in the online phase.
     */
    void preOnline();

    /**
     * Execute the online phase of the protocol.
     */
    void runOnline() override;

    /**
     * @return the output of the protocol.
     */
    vector<byte> getOutput(){
        int size = 0;
        if (id == 1) size = cf->n3;

        vector<byte> output(size);
        for (int i=0; i<size; i++){
            output[i] = out[i];
        }
        return output;
    }

};


#endif //LIBSCAPI_YAOSEPARTY_H
