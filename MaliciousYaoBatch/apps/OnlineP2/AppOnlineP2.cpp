#include <boost/thread/thread.hpp>
#include <lib/include/common/CommonMaliciousYao.hpp>
#include <lib/include/primitives/CommunicationConfig.hpp>
#include <lib/include/primitives/CryptoPrimitives.hpp>
#include <libscapi/include/circuits/GarbledCircuitFactory.hpp>
#include <libscapi/include/cryptoInfra/Protocol.hpp>
#include <lib/include/primitives/CircuitInput.hpp>
#include <lib/include/primitives/ExecutionParameters.hpp>
#include <lib/include/primitives/KProbeResistantMatrix.hpp>
#include <lib/include/OfflineOnline/primitives/BucketLimitedBundle.hpp>
#include <lib/include/OfflineOnline/primitives/BucketLimitedBundleList.hpp>
#include <lib/include/common/LogTimer.hpp>
#include <lib/include/OfflineOnline/specs/OnlineProtocolP2.hpp>
#include <lib/include/OfflineOnline/primitives/LimitedBundle.hpp>
#include <lib/include/OfflineOnline/primitives/BucketLimitedBundle.hpp>

/**
* This class runs the second party of the online protocol.
* It contain multiple
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
*
*/

const int PARTY = 2;
const string HOME_DIR = "../..";
//const string CIRCUIT_FILENAME = HOME_DIR + "/assets/circuits/AES/NigelAes.txt";
//const string CIRCUIT_INPUT_FILENAME = HOME_DIR + "/assets/circuits/AES/AESPartyTwoInputs.txt";
//const string COMM_CONFIG_FILENAME = HOME_DIR + string("/lib/assets/conf/PartiesConfig.txt");

//const string CIRCUIT_CHEATING_RECOVERY = HOME_DIR + "/assets/circuits/CheatingRecovery/UnlockP1Input.txt";
//const string BUCKETS_PREFIX_MAIN = HOME_DIR + "/data/P2/aes";
//const string BUCKETS_PREFIX_CR = HOME_DIR + "/data/P2/cr";
//const string MAIN_MATRIX = HOME_DIR + "/data/P2/aes.matrix";
//const string CR_MATRIX = HOME_DIR + "/data/P2/cr.matrix";

//file for dlog
const string NISTEC_FILE_NAME = "../../../../include/configFiles/NISTEC.txt";

int BUCKET_ID = 0;

vector<byte> getProtocolOutput(OnlineProtocolP2* protocol) {
    auto output = protocol->getOutput();
    return output.getOutput();
}

void printOutput(vector<byte> output) {
    cout << "(P2) Received Protocol output:" << endl;

    cout << "output of protocol:" << endl;
    auto outputSize = output.size();
    for (size_t i = 0; i < outputSize; i++) {
        cout << (int)output[i] << ",";
    }
    cout << endl;

    cout << "Expected output is:" << endl;
    cout << "0,1,1,0,1,0,0,1,1,1,0,0,0,1,0,0,1,1,1,0,0,0,0,0,1,1,0,1,1,0,0,0,0,1,1,0,1,0,1,0,0,1,1,1,1,0,1,1,0,0,0,0,0,1,0,0,0,0,1,1,0,0,0,0,1,1,0,1,1,0,0,0,1,1,0,0,1,1,0,1,1,0,1,1,0,1,1,1,1,0,0,0,0,0,0,0,0,1,1,1,0,0,0,0,1,0,1,1,0,1,0,0,1,1,0,0,0,1,0,1,0,1,0,1,1,0,1,0" << endl;
}


block** saveBucketGarbledTables(int size, BucketLimitedBundle * bucket){
    block** tables = new block*[size];

    for (int i=0;i<size; i++) {
        auto bundle = bucket->getLimitedBundleAt(i);
        tables[i] = (block *) _mm_malloc(bundle->getGarbledTablesSize(), SIZE_OF_BLOCK);
        memcpy((byte *) tables[i], (byte *) bundle->getGarbledTables(), bundle->getGarbledTablesSize());
    }

    return tables;

}

void restoreBucketTables(int size, BucketLimitedBundle* bucket, block** tables){
    for (int i=0;i<size; i++) {
        bucket->getLimitedBundleAt(i)->setGarbledTables(tables[i]);
    }
    delete [] tables;
}

/*************************************************************************
MAIN
**************************************************************************/
int main(int argc, char* argv[]) {

    int counter = 1;

    CmdParser parser;
    auto parameters = parser.parseArguments("", argc, argv);
    auto CIRCUIT_INPUT_FILENAME = HOME_DIR + parameters["inputFile"];
    auto BUCKETS_PREFIX_MAIN = HOME_DIR + parameters["bucketsPrefixMain"];
    auto BUCKETS_PREFIX_CR = HOME_DIR + parameters["bucketsPrefixCR"];
    auto MAIN_MATRIX = HOME_DIR + parameters["mainMatrix"];
    auto CR_MATRIX = HOME_DIR + parameters["crMatrix"];

    int N1 = stoi(parameters["n1"]);
    int B1 = stoi(parameters["b1"]);
    int B2 = stoi(parameters["b2"]);


    //set crypto primitives
    CryptoPrimitives::setCryptoPrimitives(NISTEC_FILE_NAME);
    CryptoPrimitives::setNumOfThreads(8);

    int size = N1;

    vector<shared_ptr<BucketLimitedBundle>> mainBuckets(N1), crBuckets(N1);

    for (int i = 0; i<N1; i++) {

        mainBuckets[i] = BucketLimitedBundleList::loadBucketFromFile(BUCKETS_PREFIX_MAIN + "." + to_string(BUCKET_ID) + ".cbundle");
        crBuckets[i] = BucketLimitedBundleList::loadBucketFromFile(BUCKETS_PREFIX_CR + "." + to_string(BUCKET_ID++) + ".cbundle");

    }

    // only now we start counting the running time
    string tmp = "reset times";
    byte tmpBuf[20];

    vector<long long> times(size);
    OnlineProtocolP2* protocol = new OnlineProtocolP2(argc, argv);

    auto input = CircuitInput::fromFile(CIRCUIT_INPUT_FILENAME, protocol->getMainCircuit()->getNumberOfInputs(2));

    for (int j = 0; j < 10; j+=4) {


        CryptoPrimitives::setNumOfThreads(j);

        for (int i = 0; i < size; i++) {

            int readsize = protocol->getChannel()->read(tmpBuf, tmp.size());
            //cout << "read size = " << readsize << endl;
            protocol->getChannel()->write((const byte*)tmp.c_str(), tmp.size());

            auto mainBucket = mainBuckets[i];
            auto crBucket = crBuckets[i];

            auto mainTables = saveBucketGarbledTables(B1, mainBucket.get());
            auto crTables = saveBucketGarbledTables(B2, crBucket.get());

            protocol->setBuckets(mainBucket, crBucket);
            protocol->setInput(*input);

            auto start = chrono::high_resolution_clock::now();
            protocol->run();

            auto end = chrono::high_resolution_clock::now();
            auto time = chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
            //cout << "exe no. " << i << " took " << time << " milis." << endl;
            times[i] = time;

            restoreBucketTables(B1, mainBucket.get(), mainTables);
            restoreBucketTables(B2, crBucket.get(), crTables);
        }
        int count = 0;
        for (int i = 0; i < size; i++) {
            count += times[i];
            cout << times[i] << " ";
        }

        auto average = count / size;

        cout << endl;

        //System.out.println();
        cout << size << " executions took in average " << average << " milis." << endl;


    }

    auto output = getProtocolOutput(protocol);
    printOutput(output);

    delete protocol;

    cout << "\nP2 end communication\n";

    return 0;
}
