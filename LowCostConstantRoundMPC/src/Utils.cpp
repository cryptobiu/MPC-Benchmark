//
// Created by moriya on 24/04/17.
//

#include "../include/Utils.hpp"

Utils::Utils(){
    hashSize = 32;
    blake2b_init(S, hashSize);
}

void Utils::setParameters(int id, const vector<ProtocolPartyData*> & parties, PrgFromOpenSSLAES* prg, int numThreads, ofstream * outputFile){
    //Sets the given arguments.
    this->id = id;
    this->parties = parties;
    this->prg = prg;
    this->numThreads = numThreads;
    this->outputFile = outputFile;

    //Calculates the number of threads.
    if (parties.size() <= numThreads){
        this->numThreads = parties.size();
        numPartiesForEachThread = 1;
    } else{
        this->numThreads = numThreads;
        numPartiesForEachThread = (parties.size() + numThreads - 1)/ numThreads;
    }

    numParties = parties.size() + 1;
}

void Utils::broadcast(int sendParty, byte* data, int bytesSize) {
    if (id == sendParty) {
        //send the data to the other parties
        for (int i = 0; i < parties.size(); i++) {
            parties[i]->getChannel()->write(data, bytesSize);
        }
    } else {
        //Receive the data from the send party
        if (sendParty > id){ // the id of the send party is bigger than my id
            parties[sendParty-1]->getChannel()->read(data, bytesSize);
        } else {//the id of the send party is smaller than my id
            parties[sendParty]->getChannel()->read(data, bytesSize);
        }

        //send the data to all other parties exept the send party
        vector<vector<byte>> verifyData(numParties - 1, vector<byte>(bytesSize));
        vector<thread> threads(numThreads);
        //Split the work to threads. Each thread gets some parties to work on.
        for (int t=0; t<numThreads; t++) {
            if ((t + 1) * numPartiesForEachThread <= parties.size()) {
                threads[t] = thread(&Utils::broadcastToOthers, this, data, ref(verifyData), t * numPartiesForEachThread, (t + 1) * numPartiesForEachThread, sendParty);
            } else {
                threads[t] = thread(&Utils::broadcastToOthers, this, data, ref(verifyData), t * numPartiesForEachThread, parties.size(), sendParty);
            }
        }
        for (int t=0; t<numThreads; t++){
            threads[t].join();
        }

        //check that all received values are the same
        for (int i = 0; i < parties.size(); i++) {
            if (parties[i]->getID() != sendParty) {
                for (int j = 0; j < bytesSize; j++) {
                    if (data[j] != verifyData[i][j]) {
                        *outputFile << "CHEATING!!!" << endl;
                        throw CheatAttemptException("cheating in broadcast");
                    }
                }
            }
        }
    }
}

void Utils::broadcastToOthers(byte* data, vector<vector<byte>> & verifyData, int first, int last, int sendParty){

    //Communicate with the parties that assigned to this thread.
    int bytesSize = verifyData[0].size();
    for (int i = first; i < last; i++) {
        if (parties[i]->getID() != sendParty) {
            if (id < parties[i]->getID()) {
                parties[i]->getChannel()->write(data, bytesSize);
                parties[i]->getChannel()->read(verifyData[i].data(), bytesSize);
            } else {
                parties[i]->getChannel()->read(verifyData[i].data(), bytesSize);
                parties[i]->getChannel()->write(data, bytesSize);
            }
        }
    }
}

vector<vector<byte>> Utils::coinTossing(int numElements, int elementSize){
    //Generate a seed
    block seed = prg->getRandom128();

    //commit on the seed
    vector<byte> indexArray(1);
    indexArray[0] = id;

    vector<byte> cmt(hashSize);

    blake2b_update(S, indexArray.data(), indexArray.size());
    blake2b_update(S, (byte*)&seed, NUM_BYTES);
    //Call the underlying hash's final method.
    blake2b_final(S, cmt.data(), hashSize);

    //Initialize the hash structure again to enable repeated calls.
    blake2b_init(S, hashSize);

    //broadcast the commitment
    vector<vector<byte>> receivedCmts(numParties - 1, vector<byte>(cmt.size()));
    int index = 0;
    for (int i=0; i<numParties; i++){
        if (id == i){
            broadcast(i, cmt.data(), cmt.size());
        } else {
            broadcast(i, receivedCmts[index].data(), cmt.size());
            index++;
        }
    }

    block xoredSeed = seed;
    block receivedSeed;
    index = 0;
    for (int i=0; i<numParties; i++){
        //broadcast my seed
        if (id == i){
            broadcast(i, (byte*)&seed, NUM_BYTES);
        } else {

            //get the other party's seed
            broadcast(i, (byte*)&receivedSeed, NUM_BYTES);

            //Check the received seed wih the received commitment
            indexArray[0] = i;

            blake2b_update(S, indexArray.data(), indexArray.size());
            blake2b_update(S, (byte*)&receivedSeed, NUM_BYTES);
            //Call the underlying hash's final method.
            blake2b_final(S, cmt.data(), hashSize);

            //Initialize the hash structure again to enable repeated calls.
            blake2b_init(S, hashSize);

            for (int j=0; j<cmt.size(); j++){
                if (cmt[j] != receivedCmts[index][j]){
                    *outputFile<<"CHEATING!!!"<<endl;
                    throw CheatAttemptException("cheating in coin tossing");
                }
            }

            //calculate r = s1 ⊕ · · · ⊕ sn
            xoredSeed = _mm_xor_si128(xoredSeed, receivedSeed);

            index++;
        }
    }

    int elementBytes = (elementSize % 8 == 0) ? elementSize / 8 : elementSize / 8 + 1;
    vector<byte> expandedOutput(numElements*elementBytes);

    //If the necessary bits is bigger than the sampled, expand them using a prg.
    if (numElements*elementSize > K){
        PrgFromOpenSSLAES expandPRG(numElements*elementBytes);
        SecretKey key((byte*)&xoredSeed, NUM_BYTES, "");
        expandPRG.setKey(key);
        expandPRG.getPRGBytes(expandedOutput, 0, numElements*elementBytes);

    } else {
        memcpy(expandedOutput.data(), (byte*)&xoredSeed, NUM_BYTES);
    }

    //Split the sampled bits into elements.
    vector<vector<byte>> output(numElements, vector<byte>(elementBytes));
    for (int i=0; i<numElements; i++){
        memcpy(output[i].data(), expandedOutput.data() + i*elementBytes, elementBytes);
    }
    return output;
}

void Utils::commit(block* values, int numValues) {

    //sample r ← {0, 1}^κ
    vector<byte> r(numValues*NUM_BYTES);
    prg->getPRGBytes(r, 0, numValues*NUM_BYTES);

    vector<byte> indexArray(1);
    indexArray[0] = id;

    vector<byte> cmt(hashSize * numValues);

    block* toOpen = (block*) _mm_malloc(3*numValues*NUM_BYTES, NUM_BYTES);

    //calculate c = H(i, x, r)
    for (int i = 0; i < numValues; i++) {

        memcpy((byte*) &toOpen[3*i], (byte*) &values[2*i], 2*NUM_BYTES);
        memcpy((byte*) &toOpen[3*i + 2], r.data() + i*NUM_BYTES, NUM_BYTES);

        blake2b_update(S, indexArray.data(), indexArray.size());
        blake2b_update(S, (byte*)&toOpen[3*i], NUM_BYTES*3);
        //Call the underlying hash's final method.
        blake2b_final(S, cmt.data()+ i*hashSize, hashSize);

        //Initialize the hash structure again to enable repeated calls.
        blake2b_init(S, hashSize);

    }

    //broadcasts all calculated c
    vector<vector<byte>> commitments(numParties - 1, vector<byte>(hashSize * numValues));
    int index = 0;
    for (int i = 0; i < numParties; i++) {
        //broadcast my commitments
        if (id == i) {
            broadcast(i, cmt.data(), hashSize * numValues);
        } else {

            //get the other party's commitments
            broadcast(i, commitments[index].data(), hashSize * numValues);
            index++;
        }
    }

    block* otherToVerify = (block*) _mm_malloc(3*numValues*NUM_BYTES, NUM_BYTES);
    index = 0;

    //broadcasts (x, r)
    for (int i = 0; i < numParties; i++) {
        //broadcast my x, r of all commitments
        if (id == i) {
            broadcast(i, (byte*)toOpen, numValues*NUM_BYTES*3);

        } else {

            //get the other party's x, r of all commitments
            broadcast(i, (byte*)otherToVerify, numValues*NUM_BYTES*3);

            indexArray[0] = i;
            for (int k = 0; k<numValues; k++) {

                blake2b_update(S, indexArray.data(), indexArray.size());
                blake2b_update(S, (byte*)&otherToVerify[3 * k], NUM_BYTES*3);
                //Call the underlying hash's final method.
                blake2b_final(S, cmt.data()+ k*hashSize, hashSize);

                //Initialize the hash structure again to enable repeated calls.
                blake2b_init(S, hashSize);

                //Xor all the committed values together
                values[2*k] = _mm_xor_si128(values[2*k], otherToVerify[3*k]);
                values[2*k + 1] = _mm_xor_si128(values[2*k + 1], otherToVerify[3*k + 1]);
            }

            for (int j = 0; j < hashSize*numValues; j++) {
                if (cmt[j] != commitments[index][j]) {
                    *outputFile << "CHEATING!!!" << endl;
                    throw CheatAttemptException("cheating in commitment");
                }
            }

            index++;
        }
    }

    _mm_free(toOpen);
//    cout<<"after commit"<<endl;
    _mm_free(otherToVerify);
}

void Utils::exchangeBitVector(vector<bitVector> & myData, vector<bitVector> & otherData, int first, int last){
    int size = myData[0].sizeBytes();
    for (int j=first; j<last; j++){
        if (id < parties[j]->getID()) {
            //send myData to the other party
            parties[j]->getChannel()->write((byte*)myData[j].data(), size);
            //receive the other data from the other party
            parties[j]->getChannel()->read((byte*)otherData[j].data(), size);

        } else {
            //receive the other data from the other party
            parties[j]->getChannel()->read((byte*)otherData[j].data(), size);
            //send myData to the other party
            parties[j]->getChannel()->write((byte*)myData[j].data(), size);
        }
    }
}

void Utils::roundFunction(vector<bitVector> & myData, vector<bitVector> & otherData){
    vector<thread> threads(numThreads);
    //Split the work to threads. Each thread gets some parties to work on.
    for (int t=0; t<numThreads; t++) {
        if ((t + 1) * numPartiesForEachThread <= parties.size()) {
            threads[t] = thread(&Utils::exchangeBitVector, this, ref(myData), ref(otherData), t * numPartiesForEachThread, (t + 1) * numPartiesForEachThread);
        } else {
            threads[t] = thread(&Utils::exchangeBitVector, this, ref(myData), ref(otherData), t * numPartiesForEachThread, parties.size());
        }
    }
    for (int t=0; t<numThreads; t++){
        threads[t].join();
    }
}

void Utils::exchangeBlock(block* myData, block* otherData, int first, int last, int sizeOfPiece){
    for (int j=first; j<last; j++){
        if (id < parties[j]->getID()) {
            //send myData to the other party
            parties[j]->getChannel()->write((byte*)myData + j*sizeOfPiece, sizeOfPiece);
            //receive the other data from the other party
            parties[j]->getChannel()->read((byte*)otherData + j*sizeOfPiece, sizeOfPiece);

        } else {
            //receive the other data from the other party
            parties[j]->getChannel()->read((byte*)otherData + j*sizeOfPiece, sizeOfPiece);
            //send myData to the other party
            parties[j]->getChannel()->write((byte*)myData + j*sizeOfPiece, sizeOfPiece);
        }
    }
}

void Utils::roundFunction(block* data, block* otherData, int sizeOfPiece){
    vector<thread> threads(numThreads);
    //Split the work to threads. Each thread gets some parties to work on.
    for (int t=0; t<numThreads; t++) {
        if ((t + 1) * numPartiesForEachThread <= parties.size()) {
            threads[t] = thread(&Utils::exchangeBlock, this, data, otherData, t * numPartiesForEachThread, (t + 1) * numPartiesForEachThread, sizeOfPiece);
        } else {
            threads[t] = thread(&Utils::exchangeBlock, this, data, otherData, t * numPartiesForEachThread, parties.size(), sizeOfPiece);
        }
    }
    for (int t=0; t<numThreads; t++){
        threads[t].join();
    }
}

void Utils::exchangeBlockSameInput(block* myData, block* otherData, int first, int last, int sizeOfPiece){
    for (int j=first; j<last; j++){
        if (id < parties[j]->getID()) {
            //send myData to the other party
            parties[j]->getChannel()->write((byte*)myData, sizeOfPiece);
            //receive the other data from the other party
            parties[j]->getChannel()->read((byte*)otherData + j*sizeOfPiece, sizeOfPiece);

        } else {
            //receive the other data from the other party
            parties[j]->getChannel()->read((byte*)otherData + j*sizeOfPiece, sizeOfPiece);
            //send myData to the other party
            parties[j]->getChannel()->write((byte*)myData, sizeOfPiece);
        }
    }
}

void Utils::roundFunctionSameInput(block* data, block* otherData, int sizeOfPiece){
    vector<thread> threads(numThreads);
    //Split the work to threads. Each thread gets some parties to work on.
    for (int t=0; t<numThreads; t++) {
        if ((t + 1) * numPartiesForEachThread <= parties.size()) {
            threads[t] = thread(&Utils::exchangeBlockSameInput, this, data, otherData, t * numPartiesForEachThread, (t + 1) * numPartiesForEachThread, sizeOfPiece);
        } else {
            threads[t] = thread(&Utils::exchangeBlockSameInput, this, data, otherData, t * numPartiesForEachThread, parties.size(), sizeOfPiece);
        }
    }
    for (int t=0; t<numThreads; t++){
        threads[t].join();
    }
}