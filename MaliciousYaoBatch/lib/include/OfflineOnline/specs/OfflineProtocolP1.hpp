#pragma once
#include <boost/thread/thread.hpp>
#include <libscapi/include/cryptoInfra/Protocol.hpp>
#include "../../../include/common/CommonMaliciousYao.hpp"
#include "../../../include/primitives/CommunicationConfig.hpp"
#include "../../../include/primitives/ExecutionParameters.hpp"
#include "../../../include/primitives/CryptoPrimitives.hpp"
#include "../../../include/primitives/KProbeResistantMatrix.hpp"
#include "../../../include/OfflineOnline/primitives/Bundle.hpp"
#include "../../../include/OfflineOnline/primitives/BucketBundleList.hpp"
#include "../../../include/OfflineOnline/subroutines/OfflineOtSenderRoutine.hpp"
#include "../../../include/OfflineOnline/primitives/CheatingRecoveryBundleBuilder.hpp"
#include "../../../include/OfflineOnline/subroutines/CutAndChooseProver.hpp"
#include "../../common/LogTimer.hpp"
#include <libscapi/include/interactive_mid_protocols/OTExtensionBristol.hpp>
#include "../../../include/primitives/CheatingRecoveryCircuitCreator.hpp"

using namespace std;

/**
 This class represents the first party in the offline phase of Malicious Yao protocol. <P>

 The full protocol specification is described in "Blazing Fast 2PC in the "Offline/Online Setting with Security for
 Malicious Adversaries" paper by Yehuda Lindell and Ben Riva, page 18 - section E, "The Full Protocol Specification".
*/
class OfflineProtocolP1 : public Protocol, public Malicious, public TwoParty {

private:
    boost::asio::io_service io_service;

	shared_ptr<ExecutionParameters> mainExecution;						// Parameters of the main circuit.
	shared_ptr<ExecutionParameters> crExecution;						// Parameters of the cheating recovery circuit.
	vector<shared_ptr<CommParty>> channel;									// The channel used communicate between the parties.

	shared_ptr<KProbeResistantMatrix> mainMatrix;			//The probe-resistant matrix that used to extend the main circuit's keys.
	shared_ptr<KProbeResistantMatrix> crMatrix;				//The probe-resistant matrix that used to extend the ceating recovery circuit's keys.
	shared_ptr<BucketBundleList> mainBuckets;							//Contain the main circuits.
	shared_ptr<BucketBundleList> crBuckets;				//Contain the cheating recovery circuits.
	shared_ptr<OTBatchSender> maliciousOtSender;	//The malicious OT used to transfer the keys.


	const  string HOME_DIR = "../..";
//	const string COMM_CONFIG_FILENAME = HOME_DIR + string("/lib/assets/conf/PartiesConfig.txt");
public:
	/**
	* Constructor that sets the parameters.
	* @param mainExecution Parameters of the main circuit.
	* @param crExecution Parameters of the cheating recovery circuit.
	* @param primitives Contains the low level instances to use.
	* @param communication Configuration of communication between parties.
	*/
	OfflineProtocolP1(int argc, char* argv[]);

	~OfflineProtocolP1(){
		io_service.stop();
	}

	/**
	* Runs the first party in the offline phase of the malicious Yao protocol.
	*/
    void run() override {
        runOffline();
    }

    bool hasOffline() override {return true; }
    bool hasOnline() override {return false; }
    void runOffline() override;

    /**
     * Save the buckets on the disk so the online protocol can read that.
     */
    void saveOnDisk(string bucket_prefix_main, string buckets_prefix_cr){
        mainBuckets->saveToFiles(bucket_prefix_main);
        crBuckets->saveToFiles(buckets_prefix_cr);
    }

	/**
	* @return the buckets of the main circuit.
	*/
	shared_ptr<BucketBundleList> getMainBuckets() { return this->mainBuckets; }

	/**
	* @return the buckets of the cheating recovery circuit.
	*/
	shared_ptr<BucketBundleList> getCheatingRecoveryBuckets() { return this->crBuckets; }

	vector<shared_ptr<CommParty>> getChannel() { return channel; }

private:

	/**
	* Runs the Cut and Choose protocol on the given circuit (in the ExecutionParameters object).
	* @param execution Contains parameters for the execution.
	* @param bundleBuilders Contains values used in the circuit (such as keys, wires indices).
	* @return list of buckets that holds the created circuits.
	* @throws IOException
	* @throws CheatAttemptException
	*/
	shared_ptr<BucketBundleList> runCutAndChooseProtocol(const shared_ptr<ExecutionParameters> & execution, vector<shared_ptr<BundleBuilder>> & bundleBuilders);

	/**
	* Receive KProbeResistantMatrix from P2.
	* @return the received matrix.
	* @throws CheatAttemptException
	* @throws IOException
	*/
	shared_ptr<KProbeResistantMatrix> receiveProbeResistantMatrix(); 

	/**
	* Runs the Malicious OT protocol.
	* @param execution Parameters of the circuit.
	* @param matrix The matrix that used to extend the keys.
	* @param buckets contains the circuits.
	*/
	void runObliviousTransferOnP2Keys(const shared_ptr<ExecutionParameters>& execution, 
		const shared_ptr<KProbeResistantMatrix> & matrix, const shared_ptr<BucketBundleList> & buckets);


 };