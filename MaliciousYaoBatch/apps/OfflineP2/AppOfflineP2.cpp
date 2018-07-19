
#include <lib/include/OfflineOnline/specs/OfflineProtocolP2.hpp>

using namespace std;

//home directory path for all files
const  string HOME_DIR = "../..";

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
    auto MAIN_MATRIX = HOME_DIR + parameters["mainMatrix"];
    auto CR_MATRIX = HOME_DIR + parameters["crMatrix"];
    int numOfThreads = 8; //atoi(argv[counter++]);
    CryptoPrimitives::setNumOfThreads(numOfThreads);

    string tmp = "reset times";
    cout << "tmp size = " << tmp.size() << endl;
    byte tmpBuf[20];

    OfflineProtocolP2* protocol = new OfflineProtocolP2(argc, argv);

    int totalTimes = 0;
    for (int j = 0; j < 10; j += 4) {
        cout << "in first loop. num threads = " << j << endl;
        CryptoPrimitives::setNumOfThreads(j);

        for (int i = 0; i < 5; i++) {

                protocol->getChannel()[0]->write((const byte *) tmp.c_str(), tmp.size());
                int readsize = protocol->getChannel()[0]->read(tmpBuf, tmp.size());

                // we start counting the running time just before estalishing communication
                auto start = chrono::high_resolution_clock::now();

                // and run the protocol
                protocol->run();

                // we measure how much time did the protocol take
                auto end = chrono::high_resolution_clock::now();
                auto runtime = chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
                totalTimes += runtime;
                cout << "\nOffline protocol party 2 with " << j << "threads took " << runtime << " miliseconds.\n";

        }

        cout << " average time of running OfflineP2 with " << j << " threads = " << totalTimes / 5 << endl;
        totalTimes = 0;
    }


	cout << "\nSaving buckets to files...\n";
	auto start = chrono::high_resolution_clock::now();
    protocol->saveOnDisk(BUCKETS_PREFIX_MAIN, BUCKETS_PREFIX_CR, MAIN_MATRIX, CR_MATRIX);

	auto end = chrono::high_resolution_clock::now();
	auto runtime = chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
	cout << "\nSaving buckets took " << runtime << " miliseconds.\n";

    delete protocol;

	cout << "\nP2 end communication\n";


	return 0;
}
