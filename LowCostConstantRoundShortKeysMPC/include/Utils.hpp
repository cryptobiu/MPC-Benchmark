//
// Created by moriya on 24/04/17.
//

#ifndef UTILS_H
#define UTILS_H

#include "MPCCommunication.hpp"
#include <libscapi/include/primitives/Prg.hpp>
//#include <openssl/evp.h>
#include <BLAKE2/sse/blake2.h>

using namespace std;
#define K 128
#define NUM_BYTES 16

class Utils {
private:
    int id;                                 //Party id
    int numThreads;                         //Number of threads to use in the protocol.
                                            //Usually this will be (#parties - 1) or (#parties - 1)*2
    int numPartiesForEachThread;
    vector<ProtocolPartyData*> parties;     //The communication data.
    int numParties;                         //Number of parties in the protocol

    ofstream * outputFile;                  //The file where the protocol times are written to.
    PrgFromOpenSSLAES* prg;                 //Used in the protocol in order to get random bytes

    blake2b_state S[1];                     //used in the coin tossing function
    int hashSize;

public:
    Utils();

    /**
     * Initialize the object with all the used components.
     * @param id unique number for this party
     * @param parties contains information regarding the communication
     * @param prg used to get random bytes
     * @param numThreads number of threads to use in the protocol. Usually this will be (#parties - 1) or (#parties - 1)*2.
     * @param outputFile The file where to print the times.
     */
    void setParameters(int id, const vector<ProtocolPartyData*> & parties, PrgFromOpenSSLAES* prg, int numThreads, ofstream * outputFile);

    ~Utils(){}

    /**
     * Whenever some party Pi “broadcasts” some value x, the parties must do as follows:
     * 1. Pi sends x to all other parties
     * 2. All other parties resend x to everyone except Pi
     * 3. Everyone checks that all received values are the same. If not, abort.
     * @param sendParty the party who perform the broadcast
     * @param data the data to broadcast
     * @param bytesSize size of the data
     */
    void broadcast(int sendParty, byte* data, int bytesSize);

    /**
     * The coin-tossing functionality, FRand, is used to obtain a secure, public random bit string. It can be
     * implemented with a cryptographic hash function H (e.g. SHA-256) as follows:
     * 1. Each party Pi samples a seed s i ← {0, 1}^κ
     * 2. Each party commits to their seed by broadcasting c i = H(i, si)
     * 3. After all commitments have been broadcast, open them by broadcasting si.
     * 4. For each received value si (from Pi), every party checks that si = H(i, si). If any check fails, abort.
     * 5. Output r = s1 ⊕ · · · ⊕ sn
     * For outputs longer than κ bits, r can be expanded using a PRG such as AES in counter mode.
     * @param numElements number of elements to sample
     * @param elementSize size of each sampled elements, in bits
     * @return the samples elements
     */
    vector<vector<byte>> coinTossing(int numElements = 1, int elementSize = K);

    /**
     * Commitments can be done similarly using a hash function:
     * 1. To commit to x, Pi samples r ← {0, 1}^κ and broadcasts c = H(i, x, r)
     * 2. To later open the commitment, P i broadcasts (x, r).
     * 3. All other parties check that c = H(i, x, r), and abort if the check fails.
     * @param values to commit on
     * @param numValues number of value to commit on
     */
    void commit(block* values, int numValues);

    /**
     * This function used in communication. It create threads that send/receive vectors of bitVectors to/from other parties.
     * @param data to send
     * @param sendParty the garbler id
     */
    void roundFunction(vector<byte> & data, int sendParty);

    void roundFunction(vector<vector<byte>> & data, int sendParty);
};


#endif
