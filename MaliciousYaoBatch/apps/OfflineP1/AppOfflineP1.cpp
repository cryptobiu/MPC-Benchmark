
#include <lib/include/OfflineOnline/specs/OfflineProtocolP1.hpp>


using namespace std;

//party number
const int PARTY = 1;

//home directory path for all files
const  string HOME_DIR = "../..";

//files path
//const string CIRCUIT_FILENAME = HOME_DIR + string("/assets/circuits/AES/NigelAes.txt");
//const string CIRCUIT_INPUT_FILENAME = HOME_DIR + string("/assets/circuits/AES/AESPartyOneInputs.txt");
const string COMM_CONFIG_FILENAME = HOME_DIR + string("/lib/assets/conf/PartiesConfig.txt");
//const string CIRCUIT_CHEATING_RECOVERY = HOME_DIR + string("/assets/circuits/CheatingRecovery/UnlockP1Input.txt");
//const string BUCKETS_PREFIX_MAIN = HOME_DIR + string("/data/P1/aes");
//const string BUCKETS_PREFIX_CR = HOME_DIR + string("/data/P1/cr");

//file for dlog
const string NISTEC_FILE_NAME = "../../../../include/configFiles/NISTEC.txt";


/*************************************************************************
								MAIN
**************************************************************************/
int main(int argc, char* argv[]) {

	//set crypto primitives
	CryptoPrimitives::setCryptoPrimitives(NISTEC_FILE_NAME);
    int counter = 1;

    CmdParser parser;
    auto parameters = parser.parseArguments("", argc, argv);
    auto BUCKETS_PREFIX_MAIN = HOME_DIR + parameters["bucketsPrefixMain"];
    auto BUCKETS_PREFIX_CR = HOME_DIR + parameters["bucketsPrefixCR"];


    int numOfThreads = 8;//atoi(argv[counter++]);
    CryptoPrimitives::setNumOfThreads(numOfThreads);

    string tmp = "reset times";
    cout << "tmp size = " << tmp.size() << endl;
    byte tmpBuf[20];

    OfflineProtocolP1* protocol = new OfflineProtocolP1(argc, argv);
    int totalTimes = 0;
    for (int j=0; j<10; j+=4) {
        cout<<"in first loop. num threads = "<<j<<endl;
        CryptoPrimitives::setNumOfThreads(j);

        for (int i = 0; i < 5; i++) {
                int readsize = protocol->getChannel()[0]->read(tmpBuf, tmp.size());
                protocol->getChannel()[0]->write((const byte *) tmp.c_str(), tmp.size());
            
                // we start counting the running time just before estalishing communication
                auto start = chrono::high_resolution_clock::now();

                // and run the protocol
                protocol->run();

                // we measure how much time did the protocol take
                auto end = chrono::high_resolution_clock::now();
                auto runtime = chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
                totalTimes += runtime;
                cout << "\nOffline protocol party 1 with " << j << " threads took " << runtime << " miliseconds.\n";

        }

        cout<<" average time of running OfflineP1 with "<< j << " threads = "<< totalTimes / 5 <<endl;
        totalTimes = 0;
    }


	cout << "\nSaving buckets to files...\n";
	auto start = chrono::high_resolution_clock::now();

//	auto mainBuckets = protocol->getMainBuckets();
//	auto crBuckets = protocol->getCheatingRecoveryBuckets();
//	mainBuckets->saveToFiles(BUCKETS_PREFIX_MAIN);
//	crBuckets->saveToFiles(BUCKETS_PREFIX_CR);
    protocol->saveOnDisk(BUCKETS_PREFIX_MAIN, BUCKETS_PREFIX_CR);

	auto end = chrono::high_resolution_clock::now();
	auto runtime = chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
	cout << "\nSaving buckets took " << runtime << " miliseconds.\n";

    delete protocol;

	cout << "\nP1 end communication\n";
	return 0;
}

