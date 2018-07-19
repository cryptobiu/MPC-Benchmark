//
// Created by moriya on 24/04/17.
//

#include "../include/TinyOT.hpp"

void Sharing::operator+=(const Sharing& other) {
    x = x ^ other.x;
    for (int i=0; i<numParties; i++){
        macs[i] = _mm_xor_si128(macs[i], other.macs[i]);
        keys[i] = _mm_xor_si128(keys[i], other.keys[i]);
    }
}


void Sharing::addConst(const byte val, int id, block & R) {

    if (id == 0){
        x = x ^ val;
    } else {
        if (val != 0){
            keys[0] = _mm_xor_si128(keys[0], R);
        }
    }
}

void Sharing::operator*=(const byte val) {

    x = x * val;
    if (val != 1){
        block zero = _mm_setzero_si128();
        for (int i=0; i<numParties; i++){
            macs[i] = zero;
            keys[i] = zero;
        }
    }
}

void TinyOT::init(int id, PrgFromOpenSSLAES * prg, const vector<ProtocolPartyData*> & parties, Utils* utils, int numThreads, EVP_CIPHER_CTX* aes, ofstream * outputFile, int B){

    //Sets the given arguments.
    this->id = id;
    this->prg = prg;
    this->parties = parties;
    this->utils = utils;
    this->numThreads = numThreads;
    this->aes = aes;
    this->outputFile = outputFile;
    this->B = B;
    this->c = B;

    //Calculates the number of threads.
    if (parties.size() <= numThreads){
        this->numThreads = parties.size();
        numPartiesForEachThread = 1;
        realNumThreads = numThreads; //Used in the ot. In case there are enough threads, do each one of the OT between each pair of parties separately.
    } else{
        this->numThreads = numThreads;
        numPartiesForEachThread = (parties.size() + numThreads - 1)/ numThreads;
        realNumThreads = numThreads;
    }

    numParties = parties.size() + 1;

    //Create an array of senders and receivers to use in the OT phase.
    senders = vector<osuCrypto::KosDotExtSender>(numParties - 1);
    receivers = vector<osuCrypto::KosDotExtReceiver>(numParties - 1);

    //Initialize:
    // 1. Each Party samples R<-{0,1}^k
    R = prg->getRandom128();


    osuCrypto::BitVector r((byte*)&R, K);

    //2. Every ordered pair (pi, pj) calls correlated OT, where pi sends (init, R) and pj sends (init)
    initCot(r);
}

TinyOT::~TinyOT(){
    //Deletes the allocated memory
    _mm_free(bitsSharing);
    _mm_free(xSharing);
    _mm_free(yzSharing);

    for (int i=0; i<sharings.size(); i++){
        delete sharings[i];
    }

    for (int i=0; i<yzSharings.size(); i++){
        delete yzSharings[i];
    }
}

void TinyOT::initCot(const bitVector & r){

    vector<thread> threads(numThreads);
    //Split the work to threads. Each thread gets some parties to work on.
    for (int t=0; t<numThreads; t++) {
        if ((t + 1) * numPartiesForEachThread <= parties.size()) {
            threads[t] = thread(&TinyOT::computeBaseOT, this, ref(r), t * numPartiesForEachThread, (t + 1) * numPartiesForEachThread);
        } else {
            threads[t] = thread(&TinyOT::computeBaseOT, this, ref(r), t * numPartiesForEachThread, parties.size());
        }
    }
    for (int t=0; t<numThreads; t++){
        threads[t].join();
    }
}

void TinyOT::computeBaseOT(const bitVector & r, int first, int last){
    osuCrypto::PRNG prng0(prg->getRandom128());
    std::vector<block> baseRecv(128);
    std::vector<std::array<block, 2>> baseSend(128);

    osuCrypto::NaorPinkas base;
    for (int i=first; i<last; i++){

        if (id < parties[i]->getID()){
            //This should be computed for each ordered pair (Pi, Pj)
            //First, Pi is the sender
            base.receive(r, baseRecv,prng0, parties[i]->getOTChannelFirst(), 2);

            senders[i].setBaseOts(baseRecv, r);

            //Second, Pi is the receiver
            base.send(baseSend, prng0, parties[i]->getOTChannelFirst(), 2);

            receivers[i].setBaseOts(baseSend);
        } else {
            //Pj is the receiver
            base.send(baseSend, prng0, parties[i]->getOTChannelFirst(), 2);

            receivers[i].setBaseOts(baseSend);

            //Pj is the sender
            base.receive(r, baseRecv,prng0, parties[i]->getOTChannelFirst(), 2);

            senders[i].setBaseOts(baseRecv, r);
        }
    }
}

vector<Sharing*> TinyOT::bits(int m){
    //Bits:
    //1. Each party samples m+k random bits b1, ..., bm, r1, ..., rk <-{0, 1}
    int mAndKbytes = ((m + K) % 8 == 0 ? (m+K)/8 : (m+K)/8 + 1);
    vector<byte> temp(mAndKbytes);
    prg->getPRGBytes(temp, 0, mAndKbytes);

    bitVector bits(temp.data(), m+K);

    //2. Every ordered pair (pi, pj) calls correlated OT, where pi is receiver and inputs (extends, b1, ..., bm, r1, ..., rk)
    //3. Use the previous outputs to define sharings [b1], ..., [bm], [r1], ..., [rk]

    bitsSharing = (block*) _mm_malloc(2*(m+K)*(numParties - 1)*NUM_BYTES, 32);
    auto sharings = allocateSharingsMemory(m+K, numParties - 1, bitsSharing);
    computeSharings(bits, m+K, sharings);

    //4. Check consistency of the Fcot inputs as follows:
    //(a) Call Frand to obtain random field elements χ1, . . . , χm ∈ F2κ
    vector<vector<byte>> randElements = utils->coinTossing(m);


    //(b) The parties locally compute (with arithmetic over F2κ)
    //  [c] = ([b j ] · χ j) j=1,...,m + (X^(j−1)·[rj]) j=1, ...,k

    block myC = _mm_setzero_si128();

    block* cMacs = (block *) _mm_malloc((numParties-1)*NUM_BYTES*2, 32);
    block* cKeys = (block *) _mm_malloc((numParties - 1)*NUM_BYTES*2, 32);

    for (int i=0; i<(numParties-1)*2; i++){
        cMacs[i] = _mm_setzero_si128();
        cKeys[i] = _mm_setzero_si128();
    }

    block temp0, temp1;
    Sharing *b;
    block chi, mac, key;
    for (int i=0; i<m; i++){
        //Calculate [b_i] * chi_i
        memcpy((byte*)&chi, randElements[i].data(), NUM_BYTES);
        b = sharings[i];

        if (b->getX() == 1){
            myC = _mm_xor_si128(myC, chi);
        }

        for (int j=0; j<numParties - 1; j++){
            mac = b->getMac(j);
            key = b->getKey(j);
            //multiply each mac by chi_i
            mul128(mac, chi, &temp0, &temp1);

            cMacs[j*2] = _mm_xor_si128(cMacs[j*2], temp0);
            cMacs[j*2 + 1] = _mm_xor_si128(cMacs[j*2 + 1], temp1);


            //multiply each key by chi_i
            mul128(key, chi, &temp0, &temp1);

            cKeys[j*2] = _mm_xor_si128(cKeys[j*2], temp0);
            cKeys[j*2 + 1] = _mm_xor_si128(cKeys[j*2 + 1], temp1);
        }
    }

    block x = _mm_set_epi32(0, 0, 0, 1);
    for (int i=m; i<m+K; i++){
        //Calculate [r_i] * Xi-1
        b = sharings[i];

        if (b->getX() == 1){
            myC = _mm_xor_si128(myC, x);
        }

        for (int j=0; j<numParties - 1; j++){
            mac = b->getMac(j);
            key = b->getKey(j);
            //multiply each mac by chi_i
            mul128(mac, x, &temp0, &temp1);
            cMacs[j*2] = _mm_xor_si128(cMacs[j*2], temp0);
            cMacs[j*2 + 1] = _mm_xor_si128(cMacs[j*2 + 1], temp1);

            //multiply each key by chi_i
            mul128(key, x, &temp0, &temp1);
            cKeys[j*2] = _mm_xor_si128(cKeys[j*2], temp0);
            cKeys[j*2 + 1] = _mm_xor_si128(cKeys[j*2 + 1], temp1);
        }
        if (i == m+63){
            x = _mm_set_epi32(0, 1, 0, 0);
        } else {
            x = _mm_slli_epi64(x, 1);
        }
    }
    //(c) Each Pi now has a share ci ∈ F2κ , and the MACs and keys (Mji , Kji) j != i from [c].
    //(d) Run ΠOpen on [c] to obtain c.
    block c = openExtendedSharing(myC, cMacs, cKeys);


    //(e) Each party P i defines the values
    // Zji = Mji (for j != i), Z i i = (Kji + (c + ci)· Ri) j != i and commits to the n values Zji.
    block* z = (block *) _mm_malloc(numParties*NUM_BYTES*2, 32);
    block cTag;
    for (int i=0; i<numParties; i++){
        if (i == id){
            cTag = _mm_xor_si128(myC, c);
            mul128(cTag, R, &z[2*i], &z[2*i + 1]);

            for (int j=0; j<numParties - 1; j++){
                z[2*i] = _mm_xor_si128(z[2*i], cKeys[2*j]);
                z[2*i + 1] = _mm_xor_si128(z[2*i + 1], cKeys[2*j + 1]);
            }

        } else{
            if (id > i) {
                z[2 * i] = cMacs[2 * i];
                z[2 * i + 1] = cMacs[2 * i + 1];
            } else {
                z[2 * i] = cMacs[2 * (i-1)];
                z[2 * i + 1] = cMacs[2 * (i-1) + 1];
            }
        }
    }

    utils->commit(z, numParties);

    //(f) All parties open their commitments and check that, for each j ∈ [n],  Zji = 0
    // If any check fails, abort.
    block zero = _mm_setzero_si128();
    long *ap;
    long *bp = (long*) &zero;
    //Check that the return xored values are all zeroes
    for (int i=0; i<numParties; i++){

        ap = (long*) &z[2*i];
        if ((ap[0] != bp[0]) || (ap[1] != bp[1])){
            *outputFile<<"CHEATING!!!"<<endl;
            throw CheatAttemptException("cheating in consistency check 0");
        }

        ap = (long*) &z[2*i + 1];
        if ((ap[0] != bp[0]) || (ap[1] != bp[1])){
            *outputFile<<"CHEATING!!!"<<endl;
            throw CheatAttemptException("cheating in consistency check 1");
        }
    }

    _mm_free(cMacs);
    _mm_free(cKeys);
    _mm_free(z);

    return sharings;
}

void TinyOT::mul128(__m128i a, __m128i b, __m128i *res1, __m128i *res2)
{
    __m128i tmp3, tmp4, tmp5, tmp6;

    tmp3 = _mm_clmulepi64_si128(a, b, 0x00);
    tmp4 = _mm_clmulepi64_si128(a, b, 0x10);
    tmp5 = _mm_clmulepi64_si128(a, b, 0x01);
    tmp6 = _mm_clmulepi64_si128(a, b, 0x11);

    tmp4 = _mm_xor_si128(tmp4, tmp5);
    tmp5 = _mm_slli_si128(tmp4, 8);
    tmp4 = _mm_srli_si128(tmp4, 8);
    tmp3 = _mm_xor_si128(tmp3, tmp5);
    tmp6 = _mm_xor_si128(tmp6, tmp4);
    // initial mul now in tmp3, tmp6
    *res1 = tmp3;
    *res2 = tmp6;
}

block TinyOT::openExtendedSharing(block & x, block* macs, block* keys){

    //broadcast the x values
    block* receivedX = (block *) _mm_malloc((numParties - 1)*NUM_BYTES, 32);
    int index = 0;
    for (int i=0; i<numParties; i++){
        if (id == i){
            utils->broadcast(i, (byte*)&x, NUM_BYTES);
        } else {
            utils->broadcast(i, (byte*)&receivedX[index], NUM_BYTES);
            index++;
        }
    }

    //send macs to all other parties
    block* otherMacs = (block *) _mm_malloc((numParties - 1)*NUM_BYTES*2, 32);
    utils->roundFunction(macs, otherMacs, NUM_BYTES*2);

    block mac, key0, key1;
    block temp0, temp1;
    long *ap;
    long *bp;

    block allX = x;
    //Compute x = x1 + x2 + ... + xn
    //Check that mj = ki + xj*Ri
    for (int i=0; i<numParties - 1; i++){
        allX = _mm_xor_si128(allX, receivedX[i]);

        key0 = keys[2*i];
        key1 = keys[2*i + 1];

        //compute x* R
        mul128(receivedX[i], R, &temp0, &temp1);

        //compute k + x*R
        key0 = _mm_xor_si128(key0, temp0);
        key1 = _mm_xor_si128(key1, temp1);

        ap = (long*) &otherMacs[2*i];
        bp = (long*) &key0;

        if ((ap[0] != bp[0]) || (ap[1] != bp[1])){
            *outputFile<<"CHEATING!!!"<<endl;
            throw CheatAttemptException("cheating in open extanded sharing");
        }

        ap = (long*) &otherMacs[2*i + 1];
        bp = (long*) &key1;

        if ((ap[0] != bp[0]) || (ap[1] != bp[1])){
            *outputFile<<"CHEATING!!!"<<endl;
            throw CheatAttemptException("cheating in open extanded sharing");
        }

    }

    _mm_free(otherMacs);
    _mm_free(receivedX);

    return allX;
}

void TinyOT::computeSharings(const bitVector & bits, int numOTs, vector<Sharing*> & sharings){

    //Set the bit values on the sharings
    for (int i=0; i<numOTs; i++){
        sharings[i]->setX(bits[i]);
    }

    int numOTThreads = numThreads;

    //In case there are enough threads, do each OT between each pair of parties in a different thread.
    bool isSeparate = false;
    if (parties.size() <= realNumThreads/2) {
        isSeparate = true;
        numOTThreads = parties.size()*2;
    }


    vector<thread> threads(numOTThreads);

    int index = 0;
    //Split the work to threads. Each thread gets some parties to work on.
    for (int t=0; t<numThreads; t++) {
        if ((t + 1) * numPartiesForEachThread <= parties.size()) {
            if (isSeparate) {
                threads[index++] = thread(&TinyOT::computeOTSenderReceiver, this, ref(bits), numOTs, ref(sharings),
                                    t * numPartiesForEachThread, (t + 1) * numPartiesForEachThread);
                threads[index++] = thread(&TinyOT::computeOTReceiverSender, this, ref(bits), numOTs, ref(sharings),
                                        t * numPartiesForEachThread, (t + 1) * numPartiesForEachThread);

            } else {
                threads[t] = thread(&TinyOT::computeOT, this, ref(bits), numOTs, ref(sharings),
                                    t * numPartiesForEachThread, (t + 1) * numPartiesForEachThread);
            }
        } else {
            if (isSeparate) {
                threads[index++] = thread(&TinyOT::computeOTSenderReceiver, this, ref(bits), numOTs, ref(sharings),
                                    t * numPartiesForEachThread, parties.size());
                threads[index++] = thread(&TinyOT::computeOTReceiverSender, this, ref(bits), numOTs, ref(sharings),
                                        t * numPartiesForEachThread, parties.size());

            }else {
                threads[t] = thread(&TinyOT::computeOT, this, ref(bits), numOTs, ref(sharings),
                                    t * numPartiesForEachThread, parties.size());
            }
        }
    }
    for (int t=0; t<numOTThreads; t++){
        threads[t].join();
    }
}

void TinyOT::computeOT(const bitVector & bits, int numOTs, vector<Sharing*> & sharings, int first, int last){
    osuCrypto::PRNG prng(prg->getRandom128());
    vector<block> t(numOTs);

    for (int i=first; i<last; i++) {
        vector<array<block, 2>> q(numOTs);

        if (id < parties[i]->getID()) {
            //First play as the receiver to get the mac (t)
            receivers[i].receive(bits, t, prng, parties[i]->getOTChannelFirst());
            //Second, play as the sender to get the key (q)
            senders[i].send(q, prng, parties[i]->getOTChannelFirst());

        } else {
            //First, play as the sender to get the key (q)
            senders[i].send(q, prng, parties[i]->getOTChannelFirst());

            //Second,  play as the receiver to get the mac (t)
            receivers[i].receive(bits, t, prng, parties[i]->getOTChannelFirst());
        }

        //Set the mac and key of all sharings corresponding to this party
        for (int j = 0; j < numOTs; j++) {
            sharings[j]->setMac(i, t[j]);
            sharings[j]->setKey(i, q[j][0]);

            //The LibOTe xor the results with a fixed matrix.
            //We take this as the fixed R value
            if (!firstOT) {
                R = _mm_xor_si128(q[j][0], q[j][1]);
                firstOT = true;
            }
        }

    }
}

void TinyOT::computeOTSenderReceiver(const bitVector & bits, int numOTs, vector<Sharing*> & sharings, int first, int last){
    osuCrypto::PRNG prng(prg->getRandom128());
    vector<block> t(numOTs);

    for (int i=first; i<last; i++) {
        vector<array<block, 2>> q(numOTs);

        if (id < parties[i]->getID()) {
            //play as the sender to get the key (q)
            senders[i].send(q, prng, parties[i]->getOTChannelFirst());

            //Set the key of all sharings corresponding to this party
            for (int j=0; j<numOTs; j++){
                sharings[j]->setKey(i, q[j][0]);

                if (!firstOT) {
                    R = _mm_xor_si128(q[j][0], q[j][1]);
                    firstOT = true;
                }

            }
        } else {
            //play as the receiver to get the mac (t)
            receivers[i].receive(bits, t, prng, parties[i]->getOTChannelFirst());

            //Set the mac of all sharings corresponding to this party
            for (int j = 0; j < numOTs; j++) {
                sharings[j]->setMac(i, t[j]);
            }
        }
    }
}

void TinyOT::computeOTReceiverSender(const bitVector & bits, int numOTs, vector<Sharing*> & sharings, int first, int last){
    osuCrypto::PRNG prng(prg->getRandom128());
    vector<block> t(numOTs);

    for (int i=first; i<last; i++) {
        vector<array<block, 2>> q(numOTs);

        if (id < parties[i]->getID()) {
            //play as the receiver to get the mac (t)
            receivers[i].receive(bits, t, prng, parties[i]->getOTChannelSecond());

            //Set the mac of all sharings corresponding to this party
            for (int j=0; j<numOTs; j++){
                sharings[j]->setMac(i, t[j]);
            }
        } else {
            //First, play as the sender to get the key (q)
            senders[i].send(q, prng, parties[i]->getOTChannelSecond());

            //Set the key of all sharings corresponding to this party
            for (int j = 0; j < numOTs; j++) {
                sharings[j]->setKey(i, q[j][0]);

                if (!firstOT) {
                    R = _mm_xor_si128(q[j][0], q[j][1]);
                    firstOT = true;
                }
            }
        }
    }
}

void TinyOT::ands(int m){
    //Ands:
    //To create m AND triples, first create m' = B^2m + c triples as follows:
    //1. Each party samples xl , yl ← F2 for l ∈ [m']
//    if (m >= 1024 && m < 16384){
//        B = c = 5;
//    } else if (m >= 16384 && m < 1048576){
//        B = c = 4;
//    }  else if (m > 1048576){
//        B = c = 3;
//    }
    int mTag = B*B*m + c;
    int mTagBytes = (mTag % 8 == 0 ? mTag/8 : mTag/8 + 1);
    vector<byte> temp(mTagBytes*2);

    prg->getPRGBytes(temp, 0, mTagBytes*2);

    //get the first mTag values - x
    bitVector x(temp.data(), mTag);

    //get the second mTag values - y
    bitVector y(temp.data() + mTagBytes, mTag);

    //2. Every ordered pair (pi, pj) calls correlated OT, where pi is receiver and inputs (extends, x1, ..., xm)
    //3. Pi and Pj obtain their respective value of [xil]i,j = (Mli,j , Klj,i ), such that Mli,j = Klj,i + xli· Rj ∈ Fκ^2.
    xSharing = (block*) _mm_malloc(2*mTag*(numParties-1)*NUM_BYTES, 32);
    sharings = allocateSharingsMemory(mTag, numParties - 1, xSharing);

    computeSharings(x, mTag, sharings);

    //4. For each l ∈ [mTag] and each pair of parties (Pi , Pj):
    //  (a) Pj computes ul = H(Kl), vl = H(Kl+ Rj), and sends d = ul + vl + yl to Pi
    //  (b) Pi computes wl = H(Ml) + xl · d = ul + xl · yl

    byte u, v;
    vector<vector<byte>> w(mTag, vector<byte>(numParties - 1));
    bitVector z(mTag);

    vector<bitVector> myD(numParties - 1, bitVector(mTag));
    block* keys, *macs;

    block* input = (block*) _mm_malloc(2*NUM_BYTES*(numParties-1)*mTag, 32);
    block* output = (block*) _mm_malloc(2*NUM_BYTES*(numParties-1)*mTag, 32);
    int size;
    block hashOutput;
    block xorKey;

    //In order to have better performance, we implement the hash function using an AES block cipher.
    //Prepare the input for the AES
    for (int i=0; i<mTag; i++){
        keys = sharings[i]->getKeys();

        for (int j=0; j<numParties - 1; j++){
            xorKey =  _mm_xor_si128(keys[j], R);

            memcpy((byte*)input + i*2*NUM_BYTES*(numParties - 1) + j*2*NUM_BYTES, (byte*)keys + j * NUM_BYTES, NUM_BYTES);
            memcpy((byte*)input + i*2*NUM_BYTES*(numParties - 1) + (j*2 + 1)*NUM_BYTES, (byte*)&xorKey, NUM_BYTES);

        }
    }

    //Compute the aes operation
    EVP_EncryptUpdate(aes, (byte*)output, &size, (byte*)input, 2*NUM_BYTES*(numParties-1)*mTag);

    //Calculate all u,v, d values using the AES output
    for (int i=0; i<mTag; i++){
        z[i] = 0; //We also calculate z values to avoid another loop later

        for (int j=0; j<numParties - 1; j++){
            // First play as Pj
            hashOutput = _mm_xor_si128(input[i*2*(numParties - 1) + j*2], output[i*2*(numParties - 1) + j*2]);
            u = ((byte*)&hashOutput)[0] & 1; //get the first bit of the output
            z[i] = z[i] ^ u;

            hashOutput = _mm_xor_si128(input[i*2*(numParties - 1) + j*2 + 1], output[i*2*(numParties - 1) + j*2 + 1]);
            v = ((byte*)&hashOutput)[0] & 1; //get the first bit of the output

            myD[j][i] = u ^ v ^ y[i];
        }
    }

    //send d to all other parties
    vector<bitVector> otherD(numParties - 1, bitVector(mTag));
    utils->roundFunction(myD, otherD);

    //Calculate w values
    //prepare the aes inputs
    for (int i=0; i<mTag; i++) {
        macs = sharings[i]->getMacs();

        for (int j = 0; j < numParties - 1; j++) {

            memcpy((byte*)input + i * NUM_BYTES * (numParties - 1) + j * NUM_BYTES, (byte *) macs + j * NUM_BYTES, NUM_BYTES);
        }
    }
    //Compute the aes operation
    EVP_EncryptUpdate(aes, (byte*)output, &size, (byte*)input, NUM_BYTES*(numParties-1)*mTag);

    for (int i=0; i<mTag; i++) {

        for (int j = 0; j < numParties - 1; j++) {
            // second play as Pi
            hashOutput = _mm_xor_si128(input[i*(numParties - 1) + j], output[i*(numParties - 1) + j]);

            w[i][j] = ((byte*)&hashOutput)[0] & 1; //get the first bit of the output
            w[i][j] = w[i][j] ^ ((byte)x[i] * otherD[j][i]);
        }
    }

    _mm_free(input);
    _mm_free(output);

    //5. Each party defines shares zl
    for (int i=0; i<mTag; i++){
        for (int j=0; j<numParties - 1; j++){
            z[i] = z[i] ^ w[i][j];
        }
        z[i] = z[i] ^ (x[i] * y[i]);
    }

    //6. Every ordered pair (Pi, Pj ) calls Correlated OT , where Pi is receiver and inputs (extend, {yl , zl }∈[mTag])
    bitVector yAndZ(y);
    yAndZ.append(z);

    yzSharing = (block*) _mm_malloc(2*mTag*(numParties-1)*NUM_BYTES*2, 32);
    yzSharings = allocateSharingsMemory(2*mTag, numParties - 1, yzSharing);

    computeSharings(yAndZ, 2*mTag, yzSharings);

    //7. Use the above, and the previously obtained 7 MACs on x i` , to create sharings [x`], [y`], [z`].
    vector<Sharing*> triples(mTag*3);
    for (int i=0; i<mTag; i++){
        triples[3*i] = sharings[i];
        triples[3*i + 1] = yzSharings[i];
        triples[3*i + 2] = yzSharings[i+mTag];
    }

    //Finally, run Π TripleBucketing on ([x`], [y`], [z`]) to output m correct and secure triples.
    tripleBucketing(triples);
}

vector<byte> TinyOT::open(const vector<Sharing*> & sharings){
    int size = sharings.size();
    vector<byte> x(size);
    block* myMacs = (block *) _mm_malloc(size*(numParties - 1)*NUM_BYTES, 32);

    for (int i=0; i<size; i++){
        x[i] = sharings[i]->getX();
        for (int j=0; j<numParties - 1; j++){
            myMacs[j*size + i] = sharings[i]->getMac(j);
        }
    }
    //broadcast the x values
    vector<vector<byte>> receivedX(numParties - 1,vector<byte>(x.size()));
    int index = 0;
    for (int i=0; i<numParties; i++){
        if (id == i){
            utils->broadcast(i, x.data(), x.size());
        } else {
            utils->broadcast(i, receivedX[index].data(), x.size());
            index++;
        }
    }

    //send macs to all other parties
    block* otherMacs = (block *) _mm_malloc(size*(numParties - 1)*NUM_BYTES, 32);
    utils->roundFunction(myMacs, otherMacs, size*NUM_BYTES);

    _mm_free(myMacs);

    block mac, key;
    long *ap;
    long *bp;
    //Compute x = x1 + x2 + ... + xn
    //Check that mj = ki + xj*Ri
    for (int i=0; i<numParties - 1; i++){
        for (int j=0; j<size; j++){
            x[j] = x[j] ^ receivedX[i][j];

            mac = otherMacs[i*size + j];
            key = sharings[j]->getKey(i);

            if (receivedX[i][j]) {
                key = _mm_xor_si128(key, R);
            }
            ap = (long*) &mac;
            bp = (long*) &key;
            if ((ap[0] != bp[0]) || (ap[1] != bp[1])){
                *outputFile<<"CHEATING!!!"<<endl;
                throw CheatAttemptException("cheating in open");
            }
        }
    }

    _mm_free(otherMacs);

    return x;
}

vector<byte> TinyOT::openToParty(int partyID, const vector<Sharing*> & sharings){
    int size = sharings.size();
    vector<byte> x(size);

    if (id != partyID) {
        block *myMacs = (block *) _mm_malloc(size * NUM_BYTES, 32);

        for (int i = 0; i < size; i++) {
            x[i] = sharings[i]->getX();
            if (partyID > id) {
                myMacs[i] = sharings[i]->getMac(partyID - 1);
            } else {
                myMacs[i] = sharings[i]->getMac(partyID);
            }
        }

        //send x and macs to the other party
        if (id < partyID) {
            parties[partyID - 1]->getChannel()->write((byte *) x.data(), size);
            parties[partyID - 1]->getChannel()->write((byte *) myMacs, size * NUM_BYTES);
        } else {
            parties[partyID]->getChannel()->write((byte *) x.data(), size);
            parties[partyID]->getChannel()->write((byte *) myMacs, size * NUM_BYTES);
        }
        _mm_free(myMacs);

    } else {

        for (int i = 0; i < size; i++) {
            x[i] = sharings[i]->getX();
        }
        //receive x and macs from the other parties
        vector<vector<byte>> receivedX(numParties - 1, vector<byte>(size));
        block *otherMacs = (block *) _mm_malloc(size * (numParties - 1) * NUM_BYTES, 32);

        vector<thread> threads(numThreads);
        //Split the work to threads. Each thread gets some parties to work on.
        for (int t=0; t<numThreads; t++) {
            if ((t + 1) * numPartiesForEachThread <= parties.size()) {
                threads[t] = thread(&TinyOT::readData, this, ref(receivedX), otherMacs, t * numPartiesForEachThread, (t + 1) * numPartiesForEachThread, size, size*NUM_BYTES);
            } else {
                threads[t] = thread(&TinyOT::readData, this, ref(receivedX), otherMacs, t * numPartiesForEachThread, parties.size(), size, size*NUM_BYTES);
            }
        }
        for (int t=0; t<numThreads; t++){
            threads[t].join();
        }


        block mac, key;

        long *ap;
        long *bp;
        //Compute x = x1 + x2 + ... + xn
        //Check that mj = ki + xj*Ri
        for (int i=0; i<numParties - 1; i++){
            for (int j=0; j<size; j++){
                x[j] = x[j] ^ receivedX[i][j];

                mac = otherMacs[i*size + j];
                key = sharings[j]->getKey(i);

                if (receivedX[i][j]) {
                    key = _mm_xor_si128(key, R);
                }

                ap = (long*) &mac;
                bp = (long*) &key;
                if ((ap[0] != bp[0]) || (ap[1] != bp[1])){
                //if (!(_mm_testz_si128(mac,zero))){
                    *outputFile<<"CHEATING!!!"<<endl;
                    throw CheatAttemptException("cheating in open for party");
                }
            }
        }

        _mm_free(otherMacs);
    }

    return x;
}

void TinyOT::readData(vector<vector<byte>> & receivedX, block* otherMacs, int first, int last, int xSize, int blockSize){
    for (int j = first; j < last; j++) {
        parties[j]->getChannel()->read((byte *) receivedX[j].data(), xSize);
        parties[j]->getChannel()->read((byte *) otherMacs + j * blockSize, blockSize);

    }
}


void TinyOT::tripleBucketing(vector<Sharing*> & triples){
    //Triple bucketing is done by three sub tasks:
    auto leftTriples = cutAndChoose(triples);
    auto firstTriples = checkCorrectness(leftTriples);
    removeLeakage(firstTriples);
}

vector<Sharing*> TinyOT::cutAndChoose(vector<Sharing*> & triples){
    //Select c triples
    int tripleSize = triples.size()/3;
    int bitsCount = NumberOfBits(tripleSize) + 40;
    int bytesCount = (bitsCount % 8 == 0) ? bitsCount / 8 : bitsCount / 8 + 1;
    auto choice = utils->coinTossing(c, bitsCount);

    vector<Sharing*> choosedSharing(3*c);
    vector<Sharing*> returnedTriples(triples.size() - c*3);

    vector<ulong> indices(c);
    for (int i=0; i<c; i++) {

        for (int n = bytesCount - 1; n >= 0; n--) {
            indices[i] = (indices[i] << 8) + choice[i][n];
        }

        indices[i] = indices[i] % tripleSize;
    }

    //Divide the triples into two vectors, one for the chosen triple and the other for the not chosen one.
    int chosenIndex = 0, notChosenIndex = 0;
    bool chosen = false;
    for (int i=0; i<tripleSize; i++){
        for (int j=0; j<c && !chosen;j++){
            if (indices[j] == i){
                chosen = true;
            }
        }
        if(chosen) {
            choosedSharing[chosenIndex * 3] = triples[3*i];
            choosedSharing[chosenIndex * 3 + 1] = triples[3*i + 1];
            choosedSharing[chosenIndex * 3 + 2] = triples[3*i + 2];
            chosenIndex++;
        } else {
            returnedTriples[3*notChosenIndex] = triples[3*i];
            returnedTriples[3*notChosenIndex + 1] = triples[3*i + 1];
            returnedTriples[3*notChosenIndex + 2] = triples[3*i + 2];
            notChosenIndex++;
        }
        chosen = false;
    }

    //Open the selected triples
    open(choosedSharing);

    //Returned the left triples
    return returnedTriples;
}

vector<int> TinyOT::samplePermutation(int size){

    //calculate k, the number of bits in n (the biggest index)
    int bitsCount = NumberOfBits(size) + 40;
    int bytesCount = (bitsCount % 8 == 0) ? bitsCount / 8 : bitsCount / 8 + 1;

    //call fRand to sample n indices, each with k+40 bit size
    auto choices = utils->coinTossing(size, bitsCount);

    //convert each samples index to long value x, and calculate x = mod(n) to get n values in the 1, ..., n range.
    vector<int> indices(size);
    for (int i=0; i<size; i++){
        indices[i] = i;
    }

    ulong index = 0;
    int temp;

    for (int i=0; i<size; i++){

        for (int n = bytesCount - 1; n >= 0; n--) {
            index = (index << 8) + choices[i][n];
        }

        index = index % size;
        temp = indices[i];
        indices[i] = indices[(ulong)index];
        indices[(ulong)index] = temp;

        index = 0;
    }

    return indices;

}

vector<Sharing*> TinyOT::checkCorrectness(vector<Sharing*> & triples){
    int tripleSize = triples.size()/3;
    int m = tripleSize / (B*B);

    //1. Use F Rand to sample a random permutation on {1, . . . , B^2*m}, and randomly assign the triples into
    //   mB buckets of size B, accordingly.
    auto indices = samplePermutation(tripleSize);

    vector<Sharing*> permutedTriples(triples.size());
    int index;
    //For each index i in the triples array, switch triples[i] with triples[sampledIndices[i]]
    for (int i=0; i<tripleSize; i++){
        index = indices[i];
        permutedTriples[3*i] = triples[3*index];
        permutedTriples[3*i + 1] = triples[3*index + 1];
        permutedTriples[3*i + 2] = triples[3*index + 2];
    }

    //check correctness of the first triple in the bucket, say [T ] = ([x], [y], [z]), by performing a pairwise
    // sacrifice between [T ] and every other triple in the bucket. Concretely, to check correctness of [T ] by
    // sacrificing [T0] = ([x0], [y0], [z0]):
    //  (a) Open d = x + x0 and e = y + y0 using ΠOpen.
    block* memory = (block*) _mm_malloc(m*B*2*(B-1)*(numParties - 1)*2*NUM_BYTES, 32);
    auto shares = allocateSharingsMemory(m*B*2*(B-1), numParties - 1, memory);
    Sharing *x, *y;
    for (int i=0; i<m*B; i++){

        //get the x, y, shares of the first triple
        x = permutedTriples[i*3*B];
        y = permutedTriples[i*3*B + 1];
        for (int j=1; j<B; j++){
            //calculate d = x + x0 and e = y + y0
            *shares[i*2*(B-1) + 2*(j-1)] = *x;
            *shares[i*2*(B-1) + 2*(j-1)] += *permutedTriples[i*3*B + 3*j];
            *shares[i*2*(B-1) + 2*(j-1) + 1] = *y;
            *shares[i*2*(B-1) + 2*(j-1) + 1] += *permutedTriples[i*3*B + 3*j + 1];
        }
    }

    //Run open to reveal d, e values of all triples in all buckets
    auto openVals = open(shares);

    byte d, e;
    Sharing *xShare, *yShare, *zShare;
    for (int i=m*B*(B-1); i<shares.size(); i++){
        delete shares[i];
    }


    shares.resize(m*B*(B-1));

    block* tempMemory = (block*) _mm_malloc(NUM_BYTES*2*(numParties-1), 32);
    auto temp = allocateSharingsMemory(1, numParties - 1, tempMemory)[0];

    //  (b) Compute [f] = [z] + [z0] + d · [y] + e · [x] + d · e.
    //  (c) Open [f] using Π Open and check that f = 0.
    for (int i=0; i<m*B; i++){

        //get the x, y, z values of the first triple
        xShare = permutedTriples[i*3*B];
        yShare = permutedTriples[i*3*B + 1];
        zShare = permutedTriples[i*3*B + 2];

        for (int j=1; j<B; j++){

            d = openVals[i*2*(B-1) + 2*(j-1)];
            e = openVals[i*2*(B-1) + 2*(j-1) + 1];

            *shares[i*(B-1) + j - 1] = *yShare;
            *shares[i*(B-1) + j - 1] *= d;
            *shares[i*(B-1) + j - 1] += *zShare;
            *shares[i*(B-1) + j - 1] += *permutedTriples[i*3*B + 3*j + 2];
            *temp = *xShare;
            *temp *= e;
            *shares[i*(B-1) + j - 1] += *temp;
            shares[i*(B-1) + j - 1]->addConst(d*e, id, R);
        }
    }
    _mm_free(tempMemory);
    delete temp;
    //Run open to reveal f values
    auto f = open(shares);
    for (int i=0; i<m*B*(B-1); i++){
        if (f[i] != 0){
            *outputFile<<"CHEATING!!!"<<endl;
            throw CheatAttemptException("cheating in check correctness, f is not equal to zero.");
        }
    }

    _mm_free(memory);
    for (int i=0; i<shares.size(); i++){
        delete shares[i];
    }

    //get the first trilpe in each bucket
    vector<Sharing*> firstTriples(m*B*3);
    for(int i=0; i<m*B; i++){
        firstTriples[3*i] = permutedTriples[i*3*B];
        firstTriples[3*i + 1] = permutedTriples[i*3*B + 1];
        firstTriples[3*i + 2] = permutedTriples[i*3*B + 2];

    }
    return firstTriples;

}

void TinyOT::removeLeakage(vector<Sharing*> & triples){
    int tripleSize = triples.size()/3;
    int m = tripleSize / B;

    //1. Use F Rand to sample a random permutation on {1, . . . , B^2*m}, and randomly assign the triples into
    //   mB buckets of size B, accordingly.
    auto indices = samplePermutation(tripleSize);

    vector<Sharing*> permutedTriples(triples.size());
    for (int i=0; i<tripleSize; i++){
        permutedTriples[3*i] = triples[3*indices[i]];
        permutedTriples[3*i + 1] = triples[3*indices[i] + 1];
        permutedTriples[3*i + 2] = triples[3*indices[i] + 2];
    }

    //   (a) Open d = y + y 0 using Π Open.
    block* memory = (block*) _mm_malloc(2*m*(B-1)*(numParties - 1)*NUM_BYTES, 32);
    auto dShares = allocateSharingsMemory(m*(B-1), numParties - 1, memory);
    Sharing *x, *y, *z;
    for (int i=0; i<m; i++){
        //calculate the y + y' shares
        y = permutedTriples[i*3*B + 1];

        for (int j=1; j<B; j++){
            *dShares[i*(B-1) + j - 1] = *y;
            *dShares[i*(B-1) + j - 1] += *permutedTriples[i*3*B + 3*j + 1];
        }
    }

    //Run open to reveal d values
    auto d = open(dShares);

    _mm_free(memory);
    for (int i=0; i<dShares.size(); i++){
        delete dShares[i];
    }

    multiplicationTriples.resize(m);

    //  (b) Compute [z''] = d · [x'] + [z] + [z'] and [x''] = [x] + [x'].
    //  (c) Output the triple [x''], [y], [z''].
    for (int i=0; i<m; i++){
        x = permutedTriples[i*3*B];
        z = permutedTriples[i*3*B + 2];
        for (int j=1; j<B; j++){
            *x += *permutedTriples[i*3*B + 3*j];
            *permutedTriples[i*3*B + 3*j] *= d[i*(B-1) + j - 1];
            *z += *permutedTriples[i*3*B + 3*j];
            *z += *permutedTriples[i*3*B + 3*j + 2];
        }

        multiplicationTriples[i].setTriple(x, permutedTriples[i*3*B + 1], z);
    }

}

void TinyOT::multiply(const vector<Sharing*> & u, const vector<Sharing*> & v, vector<Sharing*> & z){

    //Given a multiplication triple [a], [b], [c] and two shared values [x], [y], the parties compute a sharing of x·y.
    int multSize = u.size();
    vector<Sharing*> multTriple;

    // 1. Each party broadcasts di = ai + xi and ei = bi + yi.
    // 2. Compute d = d1 + ... + dn , e = e1 + ... + en , and run Open to check the MACs on [d] and [e].
    block* memory = (block*) _mm_malloc(2*2*multSize*(numParties - 1)*NUM_BYTES, 32);
    auto dAndE = allocateSharingsMemory(2*multSize, numParties - 1, memory);
    for (int i=0; i<multSize; i++){
        multTriple = multiplicationTriples[i].getTriple();
        //calc d
        *dAndE[2*i] = *multTriple[0];
        *dAndE[2*i] += *u[i];

        *dAndE[2*i + 1] = *multTriple[1];
        *dAndE[2*i + 1] += *v[i];

    }

    auto vals = open(dAndE);

    _mm_free(memory);
    for (int i=0; i<dAndE.size(); i++){
        delete dAndE[i];
    }


    // 3. Output [z] = [c] + d · [b] + e · [a] + d · e = [x · y].
    byte d, e;
    for (int i=0; i<multSize; i++){
        multTriple = multiplicationTriples[i].getTriple();
        d = vals[2*i];
        e = vals[2*i + 1];

        *multTriple[1] *= d;
        *z[i] = *multTriple[2];
        *z[i] += *multTriple[1];
        *multTriple[0] *= e;
        *z[i] += *multTriple[0];
        z[i]->addConst(d*e, id , R);
    }
}

vector<Sharing*> TinyOT::allocateSharingsMemory(int numSharings, int numParties, block* memory){
    //assign each sharing with the right place in the memory.
    vector<Sharing*> output(numSharings);
    for (int i=0; i<numSharings; i++){
        output[i] = new Sharing(numParties, memory + i*2*numParties, memory + (i*2 + 1)*numParties);
    }


    return output;
}
