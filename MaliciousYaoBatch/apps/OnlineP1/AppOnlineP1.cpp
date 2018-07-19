#include <boost/thread/thread.hpp>
#include <lib/include/common/CommonMaliciousYao.hpp>
#include <lib/include/primitives/CommunicationConfig.hpp>
#include <lib/include/primitives/CryptoPrimitives.hpp>
#include <libscapi/include/circuits/GarbledCircuitFactory.hpp>
#include <libscapi/include/cryptoInfra/Protocol.hpp>
#include <lib/include/primitives/CheatingRecoveryCircuitCreator.hpp>
#include <lib/include/primitives/CircuitInput.hpp>
#include <lib/include/primitives/ExecutionParameters.hpp>
#include <lib/include/OfflineOnline/primitives/BucketBundleList.hpp>
#include <lib/include/common/LogTimer.hpp>
#include <lib/include/OfflineOnline/specs/OnlineProtocolP1.hpp>

using namespace std;

//party number
const int PARTY = 1;

const string HOME_DIR = "../..";

//const string CIRCUIT_FILENAME = HOME_DIR + "/assets/circuits/AES/NigelAes.txt";
//const string CIRCUIT_INPUT_FILENAME = HOME_DIR + "/assets/circuits/AES/AESPartyOneInputs.txt";
//const string COMM_CONFIG_FILENAME = HOME_DIR + string("/lib/assets/conf/PartiesConfig.txt");

//const string CIRCUIT_CHEATING_RECOVERY = HOME_DIR + "/assets/circuits/CheatingRecovery/UnlockP1Input.txt";
//const string BUCKETS_PREFIX_MAIN = HOME_DIR + "/data/P1/aes";
//const string BUCKETS_PREFIX_CR = HOME_DIR + "/data/P1/cr";

//file for dlog
const string NISTEC_FILE_NAME = "../../../../include/configFiles/NISTEC.txt";

int BUCKET_ID = 0;

int main(int argc, char* argv[]) {

//	boost::thread t(boost::bind(&boost::asio::io_service::run, &io_service));

    int counter = 1;

	CmdParser parser;
	auto parameters = parser.parseArguments("", argc, argv);
    auto CIRCUIT_INPUT_FILENAME = HOME_DIR + parameters["inputFile"];
    auto BUCKETS_PREFIX_MAIN = HOME_DIR + parameters["bucketsPrefixMain"];
    auto BUCKETS_PREFIX_CR = HOME_DIR +  parameters["bucketsPrefixCR"];

	//set crypto primitives
	CryptoPrimitives::setCryptoPrimitives(NISTEC_FILE_NAME);
	CryptoPrimitives::setNumOfThreads(8);

    int N1 = stoi(parameters["n1"]);
	// we load the bundles from file
	vector<shared_ptr<BucketBundle>> mainBuckets(N1), crBuckets(N1);
	int size = N1;

	for (int i = 0; i<N1; i++) {

		mainBuckets[i] = BucketBundleList::loadBucketFromFile(BUCKETS_PREFIX_MAIN + "." + to_string(BUCKET_ID) + ".cbundle");
		crBuckets[i] = BucketBundleList::loadBucketFromFile(BUCKETS_PREFIX_CR + "." + to_string(BUCKET_ID++) + ".cbundle");
	}

    auto input = CircuitInput::fromFile(CIRCUIT_INPUT_FILENAME, mainBuckets[0]->getBundleAt(0)->getNumberOfInputLabelsX());
	// only now we start counting the running time
	string tmp = "reset times";
	cout << "tmp size = " << tmp.size() << endl;
	byte tmpBuf[20];

    OnlineProtocolP1* protocol = new OnlineProtocolP1(argc, argv);
	vector<long long> times(size);
    for (int j = 0; j < 10; j+=4) {
		//cout << "num of threads = " << j << endl;
		CryptoPrimitives::setNumOfThreads(j);

		for (int i = 0; i < size; i++) {
			protocol->getChannel()->write((const byte*)tmp.c_str(), tmp.size());
			int readsize = protocol->getChannel()->read(tmpBuf, tmp.size());

			auto mainBucket = mainBuckets[i];
			auto crBucket = crBuckets[i];
			protocol->setBuckets(*mainBucket, *crBucket);
            protocol->setInput(input);

            auto start = chrono::high_resolution_clock::now();

			protocol->run();
            auto end = chrono::high_resolution_clock::now();
			auto time = chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
			//cout << "exe no. " << i << " took " << time << " millis." << endl;
			times[i] = time;
		}

		int count = 0;
		for (int i = 0; i < size; i++) {
			count += times[i];
            cout <<times[i] << " ";
		}

		auto average = count / size;

		cout << endl;

		//System.out.println();
		cout << size << " executions took in average" << average << " milis." << endl;
	}

    delete protocol;

	cout << "\nP1 end communication\n";

	return 0;
}
