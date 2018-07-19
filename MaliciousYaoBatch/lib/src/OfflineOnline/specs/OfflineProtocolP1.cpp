#include "../../../include/OfflineOnline/specs/OfflineProtocolP1.hpp"
OfflineProtocolP1::OfflineProtocolP1(int argc, char* argv[]) : Protocol ("OfflineMaliciousYao", argc, argv) {

	shared_ptr<CommunicationConfig> commConfig (new CommunicationConfig(HOME_DIR + arguments["partiesFile"], 1, io_service));
	this->channel = commConfig->getCommParty();

	cout << "\nP1 start communication\n";

	//make connection
	for (int i = 0; i < channel.size(); i++)
		channel[i]->join(500, 5000);

	auto maliciousOtServer = commConfig->getMaliciousOTServer();
	maliciousOtSender = make_shared<OTExtensionBristolSender>(maliciousOtServer->getPort(), false, channel[0]);

    //make circuit
    vector<shared_ptr<GarbledBooleanCircuit>> mainCircuit;
    vector<shared_ptr<GarbledBooleanCircuit>> crCircuit;

    int numOfThreads = CryptoPrimitives::getNumOfThreads();
    if (numOfThreads == 0)
        numOfThreads = 1;

    mainCircuit.resize(numOfThreads);
    crCircuit.resize(numOfThreads);

    for (int i = 0; i<numOfThreads; i++) {
        mainCircuit[i] = shared_ptr<GarbledBooleanCircuit>(GarbledCircuitFactory::createCircuit(HOME_DIR + arguments["circuitFile"],
                                                                                                GarbledCircuitFactory::CircuitType::FIXED_KEY_FREE_XOR_HALF_GATES, true));
        crCircuit[i] = shared_ptr<GarbledBooleanCircuit>(CheatingRecoveryCircuitCreator(HOME_DIR + arguments["circuitCRFile"], mainCircuit[i]->getNumberOfGates()).create());
    }

    mainExecution = make_shared<ExecutionParameters>(nullptr, mainCircuit, stoi(arguments["n1"]), stoi(arguments["s1"]), stoi(arguments["b1"]), stod(arguments["p1"]));
    crExecution = make_shared<ExecutionParameters>(nullptr, crCircuit, stoi(arguments["n2"]), stoi(arguments["s2"]), stoi(arguments["b2"]), stod(arguments["p2"]));
}

void OfflineProtocolP1::runOffline()
{

	//LogTimer timer("Offline protocol");
	// Pick master proof of cheating (true for all buckets!!!).
	auto proofOfCheating = CryptoPrimitives::getAES()->generateKey(KEY_SIZE);

	//timer.reset("receiving probe resistant matrices");
	// Receive matrices from p2.
	mainMatrix = receiveProbeResistantMatrix();
	crMatrix = receiveProbeResistantMatrix();

	//timer.stop();

	//timer.reset("init bundle builders...");

	//make circuit
	vector<shared_ptr<BundleBuilder>> mainBundleBuilders;
	vector<shared_ptr<BundleBuilder>> crBundleBuilders;

	int numOfThread = CryptoPrimitives::getNumOfThreads();
	if (numOfThread == 0)
		numOfThread = 1;

	mainBundleBuilders.resize(numOfThread);
	crBundleBuilders.resize(numOfThread);

	for (int i = 0; i<numOfThread; i++) {
		mainBundleBuilders[i] = make_shared<BundleBuilder>(mainExecution->getCircuit(i), mainMatrix);
		crBundleBuilders[i] = make_shared<CheatingRecoveryBundleBuilder>(crExecution->getCircuit(i), crMatrix, proofOfCheating);
	}

	//timer.stop();

	//timer.reset("runCutAndChooseProtocol(AES)");
	//Run Cut and Choose protocol on the main circuit.
	mainBuckets = runCutAndChooseProtocol(mainExecution, mainBundleBuilders);

	//timer.stop();
	//timer.reset("runCutAndChooseProtocol(CR)");
	//Run Cut and Choose protocol on the cheating recovery circuit.
	crBuckets = runCutAndChooseProtocol(crExecution, crBundleBuilders);

	//timer.stop();

	//timer.reset("runObliviousTransferOnP2Keys(AES)");
	//Run OT on p2 keys of the main circuit.
	runObliviousTransferOnP2Keys(mainExecution, mainMatrix, mainBuckets);
	//timer.stop();

	//timer.reset("runObliviousTransferOnP2Keys(CR)");
	//Run OT on p2 keys of the cheating recovery circuit.
	runObliviousTransferOnP2Keys(crExecution, crMatrix, crBuckets);
	//timer.stop();
}

shared_ptr<BucketBundleList> OfflineProtocolP1::runCutAndChooseProtocol(const shared_ptr<ExecutionParameters> & execution, vector<shared_ptr<BundleBuilder>> & bundleBuilders)
{
    CutAndChooseProver prover(execution, channel, bundleBuilders);
	prover.run();
	return prover.getBuckets();
}

shared_ptr<KProbeResistantMatrix> OfflineProtocolP1::receiveProbeResistantMatrix()
{
	shared_ptr<KProbeResistantMatrix> kprMatrix;
	readSerialize(kprMatrix, this->channel[0].get());
	return kprMatrix;
}

void OfflineProtocolP1::runObliviousTransferOnP2Keys(const shared_ptr<ExecutionParameters>& execution, const shared_ptr<KProbeResistantMatrix> & matrix, 
	const shared_ptr<BucketBundleList> & buckets)
{
	//Create and run malicious OT routine.
	OfflineOtSenderRoutine otSender(execution, matrix, buckets, maliciousOtSender);
	otSender.run();
}
