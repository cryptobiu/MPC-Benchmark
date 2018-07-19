//
// Created by moriya on 24/04/17.
//

#ifndef TINYOT_H
#define TINYOT_H

#include "cryptoTools/Crypto/PRNG.h"
#include "libOTe/Base/naor-pinkas.h"
#include "libOTe/TwoChooseOne/KosDotExtSender.h"
#include "libOTe/TwoChooseOne/KosDotExtReceiver.h"
#include "../include/MPCCommunication.hpp"
#include "../include/Utils.hpp"
#include <libscapi/include/primitives/Prg.hpp>
#include <BLAKE2/sse/blake2.h>

using namespace std;


/*
 * This class represents a sharing of a wire.
 *
 * A sharing is, as defined in the protocol:
 * For x ∈ {0, 1} held by Pi , define the following two-party MAC representation, as used in 2-party TinyOT:
 * [x] i,j = (x, M ji , K ij), Mji = Kij ⊕ x · Rj where Pi holds x and a MAC Mji ∈ {0, 1}^κ , and  j holds a local,
 * random MAC key Kij ∈ {0, 1}^κ , as well as the fixed, global MAC key Rj.
 *
 * Similarly, we define the n-party representation of an additively shared value x = x 1 ⊕ · · · ⊕ x n :
 * [x] = (xi , {Mji , Kji } j != i ) i∈[n] , Mji = Kij ⊕ xi · Rj where each party Pi holds the n − 1 MACs Mji on xi,
 * as well as the keys Kji on each xj , for j != i, and a global key Ri.
 *
 * Actually, a sharing object contains the bit value x, the mac values and key values for all other parties.
 */
class Sharing {
private:
    byte x;
    int numParties;
    block* macs = nullptr;
    block* keys = nullptr;

public:
    Sharing(){}

    /**
     * Constructor that gets a pointer to a previously allocated memory and set it to the macs and keys pointers.
     * We prefer setting a pointer instead of allocate it in the constructor, in order to allocate a big memory at once instead of many small memory areas.
     * This makes better performance.
     * @param numParties number of parties in the protocol
     * @param macs a pointer to a previously allocated memory
     * @param keys a pointer to a previously allocated memory
     */
    Sharing(int numParties, block* macs, block* keys) : numParties(numParties) {
        this->macs = macs;
        this->keys = keys;
    }

    Sharing(const Sharing & other) {
        numParties = other.numParties;

        x = other.x;
        memcpy((byte*)macs, (byte*)other.macs, numParties*NUM_BYTES);
        memcpy((byte*)keys, (byte*)other.keys, numParties*NUM_BYTES);
    }

    Sharing(Sharing && other) {

        x = other.x;
        numParties = other.numParties;
        macs = other.macs;
        keys = other.keys;
        other.macs = nullptr;
        other.keys = nullptr;
    }

    ~Sharing(){}

    Sharing & operator= (const Sharing & other) {
        x = other.x;
        numParties = other.numParties;
        memcpy((byte *) macs, (byte *) other.macs, numParties * NUM_BYTES);
        memcpy((byte *) keys, (byte *) other.keys, numParties * NUM_BYTES);

        return *this;
    }

    Sharing & operator= (Sharing && other) {
        x = other.x;
        numParties = other.numParties;
        block* tempMacs = macs;
        block* tempKeys = keys;
        macs = other.macs;
        keys = other.keys;
        other.macs = tempMacs;
        other.keys = tempKeys;

        return *this;
    }

    void setX(byte x) { this->x = x; }
    byte getX() const { return x; }
    void setMac(int partyID, const block mac) { macs[partyID] = mac; }
    block getMac(int partyID) const { return macs[partyID]; }
    void setKey(int partyID, const block key) { keys[partyID] = key; }
    block getKey(int partyID) const { return keys[partyID]; }

    block* getMacs(){ return macs; }
    block* getKeys(){ return keys; }

    void operator+=(const Sharing& other);
    void addConst(const byte val, int id, block & R);
    void operator*=(const byte val);
};

/**
 * This class represents a multiplication triple.
 */
class Triple {
private:
    vector<Sharing*> triple;

public:
    Triple(){
        triple.resize(3);
    }

    vector<Sharing*> getTriple() { return triple; }

    void setTriple(Sharing* x, Sharing* y, Sharing* z){
        triple[0] = x;
        triple[1] = y;
        triple[2] = z;
    }
};

/**
 * This class represents the Tiny OT protocol
 */
class TinyOT {
private:
    int id;             //Party id
    int B;              //Bucket size
    int c;              //Number of triples to open during the cut and choose phase of the triple bucketing.

    //Threads handling.
    int numThreads, realNumThreads;
    int numPartiesForEachThread;

    Utils* utils;                           //Utility class that perform some of the protocol functionalities, such as broadcast
    vector<ProtocolPartyData*> parties;     //The communication data.
    int numParties;                         //Number of parties in the protocol
    PrgFromOpenSSLAES* prg;                 //Used in the protocol in order to get random bytes
    EVP_CIPHER_CTX* aes;                    //Used in the protocol in order to encrypt data
    ofstream * outputFile;                  //The file where the protocol times are written to.

    block R; //Fixed global R value that unique for this party
    bool firstOT = false;

    vector<osuCrypto::KosDotExtSender> senders;     //The senders of the OT
    vector<osuCrypto::KosDotExtReceiver> receivers; //The receives of the OT

    vector<Sharing*> sharings, yzSharings;      //Vectors which contain sharings used in the and function.
    block* bitsSharing, *xSharing, *yzSharing;  //memory of the sharings. we keep this in order to delete all the sharings memory at once.

    //Triples that are generated by the ands function and are used in the multiply function
    vector<Triple> multiplicationTriples;

    /**
     * 1. Each party P i samples R i ← {0, 1}^κ. We get the sampled R as a parameter.
     * 2. Every ordered pair (Pi , Pj) calls F COT , where Pi sends (init, Ri) and Pj sends (init).
     * @param r the samples Ri <-{0, 1}^κ
     */
    void initCot(const bitVector & r);

    /**
     * Executes the OT between each pair of parties in order to create a sharing.
     * @param bits sigma
     * @param numOTs number of sharings
     * @param sharings vector of sharing to fill in the function
     */
    void computeSharings(const osuCrypto::BitVector & bits, int numOTs, vector<Sharing*> & sharings);

    /**
     * Put the sharings into buckets.
     * @param triples all the created sharings
     */
    void tripleBucketing(vector<Sharing*> & triples);

    /**
     * Using F Rand, the parties select at random c triples, which are opened with ΠOpen and checked for correctness.
     * If any triple is incorrect, abort.
     * @param triples all the created sharings
     * @return the sharings without those which opened
     */
    vector<Sharing*> cutAndChoose(vector<Sharing*> & triples);

    /**
     * The parties now have B^2 m unopened triples.
     * 1. Use FRand to sample a random permutation on {1, . . . , B^2*m}, and randomly assign the triples into
     * mB buckets of size B, accordingly.
     * 2. For each bucket, check correctness of the first triple in the bucket, say [T ] = ([x], [y], [z]), by per-
     * forming a pairwise sacrifice between [T ] and every other triple in the bucket. Concretely, to check
     * correctness of [T ] by sacrificing [T 0 ] = ([x 0 ], [y 0 ], [z 0 ]):
     * (a) Open d = x + x 0 and e = y + y 0 using Π Open.
     * (b) Compute [f ] = [z] + [z 0 ] + d · [y] + e · [x] + d · e.
     * (c) Open [f ] using Π Open and check that f = 0.
     * @param triples the sharings that left after the cut and choose phase
     * @return the first sharing in each bucket
     */
    vector<Sharing*> checkCorrectness(vector<Sharing*> & triples);

    /**
     * Taking the first triple in each bucket from the previous step, the parties are left with Bm triples.
     * They remove any potential leakage on the [x] bits of these as follows:
     * 1. Place the triples into m buckets of size B.
     * 2. For each bucket, combine all B triples into a single triple. Specifically, combine the first triple
     * ([x], [y], [z]) with [T'] = ([x'], [y'], [z']), for every other triple T 0 in the bucket:
     * (a) Open d = y + y 0 using Π Open.
     * (b) Compute [z''] = d · [x'] + [z] + [z'] and [x''] = [x] + [x'].
     * (c) Output the triple [x''], [y], [z''].
     *
     * The outputed triples are saved in the multiplicationTriples member.
     * @param triples the sharings that left after the check correctness phase
     */
    void removeLeakage(vector<Sharing*> & triples);

    /**
     * Use FRand to sample a random permutation on {1, . . . , B^2*m}
     * We do the sampling as follows:
     * 1. calculate k, the number of bits in n (the biggest index)
     * 2. call fRand to sample n indices, each with k+40 bit size.
     * 3. convert each samples index to long value x, and calculate x = mod(n) to get n values in the 1, ..., n range.
     * The permutation is performed af follows:
     * For each index i in the triples array:
     *      switch triples[i] with triples[sampledIndices[i]]
     *
     * @param size number of indices to sample.
     * @return the sampled indices
     */
    vector<int> samplePermutation(int size);

    /**
     * Perform the open functionality on an extanded sharing, where each mac and key is 2-blocks size (instead of 1, in the usual case)
     * @param x shared value
     * @param macs the extended macs values
     * @param keys the extanded keys values
     * @return the real value calculated by all parties during the open functionality.
     */
    block openExtendedSharing(block & x, block* macs, block* keys);

    /**
     * Perform polynomial multiplication of a and b.
     * The result is a 2-blocks polynomial
     * @param a first polynomial to multiply
     * @param b second polynomial to multiply
     * @param res1 first part of the result
     * @param res2 second part of the result
     */
    void mul128(__m128i a, __m128i b, __m128i *res1, __m128i *res2);

    /**
     * Read data from all other parties using threads in the openToParty functionality.
     * @param receivedX a place where to put the received x
     * @param otherMacs a place where to put the received macs
     * @param first first party to received from
     * @param last last party to received from
     * @param xSize number of x bytes to read
     * @param blockSize number of macs bytes to read
     */
    void readData(vector<vector<byte>> & receivedX, block* otherMacs, int first, int last, int xSize, int blockSize);

    /**
     * Call the LibOTe library to perform OT between this party and every other party in the range [first, last].
     * There are actually two Ots between each pair of parties. This function run both OTs one after another.
     * This is done using threads.
     * @param bits sigma
     * @param numOTs number of ots (sharing) to execute
     * @param sharings vector of sharing to fill aith the OT outputs
     * @param first first party to execute OT with
     * @param last last party to execute OT with
     */
    void computeOT(const bitVector & bits, int numOTs, vector<Sharing*> & sharings, int first, int last);

    /**
     * Call the LibOTe library to perform OT between this party and every other party in the range [first, last].
     * There are actually two Ots between each pair of parties. This function run one of them.
     * This is done using threads.
     * @param bits sigma
     * @param numOTs number of ots (sharing) to execute
     * @param sharings vector of sharing to fill aith the OT outputs
     * @param first first party to execute OT with
     * @param last last party to execute OT with
     */
    void computeOTSenderReceiver(const bitVector & bits, int numOTs, vector<Sharing*> & sharings, int first, int last);

    /**
     * Call the LibOTe library to perform OT between this party and every other party in the range [first, last].
     * There are actually two Ots between each pair of parties. This function run one of them.
     * This is done using threads.
     * @param bits sigma
     * @param numOTs number of ots (sharing) to execute
     * @param sharings vector of sharing to fill aith the OT outputs
     * @param first first party to execute OT with
     * @param last last party to execute OT with
     */
    void computeOTReceiverSender(const bitVector & bits, int numOTs, vector<Sharing*> & sharings, int first, int last);

    /**
     * Call the LibOTe library to perform base OT between this party and every other party in the range [first, last].
     * This is done using threads.
     * @param r fixed delta
     * @param first first party to execute OT with
     * @param last last party to execute OT with
     */
    void computeBaseOT(const bitVector & r, int first, int last);


public:
    TinyOT(){}

    /**
     * destructor that deleted all the allocated memory.
     */
    ~TinyOT();

    /**
     * Initialize the object with all the used components.
     * @param id unique number for this party
     * @param prg used to get random bytes
     * @param parties contains information regarding the communication
     * @param utils used to perform some of the protocol functionalities
     * @param numThreads number of threads to use in the protocol. Usually this will be (#parties - 1) or (#parties - 1)*2.
     * @param aes used in the protocol
     * @param outputFile The file where to print the times.
     * @param B bucket size
     */
    void init(int id, PrgFromOpenSSLAES * prg, const vector<ProtocolPartyData*> & parties, Utils* utils, int numThreads, EVP_CIPHER_CTX* aes, ofstream * outputFile, int B);

    /**
     * Create m random shared bits [b1], . . . , [bm].
     * @param m number of required sharings
     * @return the created sharings
     */
    vector<Sharing*> bits(int m);

    /**
     * Create m AND triples.
     * a triple is 3 sharing (x, y, z) such that z = x*y.
     * The created triples are saved in the multiplicationTriples member of the class.
     * @param m number of required triples
     */
    void ands(int m);

    /**
     * Given a multiplication triple [a], [b], [c] and two shared values [x], [y], the parties compute a sharing of
     * x · y as follows:
     * 1. Each party broadcasts d i = a i + x i and e i = b i + y i.
     * 2. Compute d = i d i , e = i e i , and run Π Open to check the MACs on [d] and [e].
     * 3. Output [z] = [c] + d · [b] + e · [a] + d · e = [x · y].
     *
     * We perform multiple multiplication at one call to multiply
     * @param u an array contains the first values to multiply
     * @param v an array contains the second values to multiply
     * @param z an array to fill with the multiplications results.
     */
    void multiply(const vector<Sharing*> & u, const vector<Sharing*> & v, vector<Sharing*> & z);

    /**
     * To open a shared value [x] to all parties:
     * 1. Each party Pi broadcasts its share xi, and sends the MAC Mji to Pj , for j != i.
     * 2. All parties compute x = x1 + · · · + xn .
     * 3. Each Pi has received MACs Mij , for j != i, and checks that
     *                  Mij = Kji + xj · Ri.
     * If any check fails, broadcast ⊥ and abort.
     * @param sharings a list of sharings to open
     * @return the real values computed by all the parties
     */
    vector<byte> open(const vector<Sharing*> & sharings);

    /**
     * To open a shared value [x] to only Pj:
     * 1. Each party Pi , for i != j, sends its share xi and MAC Mji to Pj.
     * 2. Pj computes x = x1 + · · · + xn , and checks that, for each i != j
     *                  Mji = Kij + xi · Rj
     * If any check fails, broadcast ⊥ and abort.
     * @param partyID the party to parform open to
     * @param sharings  a list of sharings to open
     * @return party Pj returns the real values of the sharings; The others returns their sharings values.
     */
    vector<byte> openToParty(int partyID, const vector<Sharing*> & sharings);

    block getR(){ return R; }

    /**
     * A sharing object contains two pointers to blocks.
     * In order to have better performance, we allocate a big bench of memory at once instead of allocate small memory for each sharing.
     * After that we assign each sharing to a part of the allocated memory.
     * The function gets a pointer and allocate it with the required memory size.
     * @param numSharings number of sharings to create memory for.
     * @param numParties number of parties in the protocol. This is necessary since the number of macs and keys depends on the number of parties.
     * @param memory a pointer to blocks to allocate
     * @return a created sharings vector assigned to the created memory.
     */
    vector<Sharing*> allocateSharingsMemory(int numSharings, int numParties, block* memory);
};

#endif
