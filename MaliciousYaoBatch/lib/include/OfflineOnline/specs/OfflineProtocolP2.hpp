#pragma once
#include <boost/thread/thread.hpp>

#include <libscapi/include/cryptoInfra/Protocol.hpp>
#include "../../../include/primitives/KProbeResistantMatrix.hpp"
#include "../../../include/primitives/CommunicationConfig.hpp"
#include "../../../include/OfflineOnline/subroutines/CutAndChooseVerifier.hpp"
#include "../../../include/OfflineOnline/subroutines/OfflineOtReceiverRoutine.hpp"
#include "../../common/LogTimer.hpp"
#include <libscapi/include/interactive_mid_protocols/OTExtensionBristol.hpp>
#include "../../../include/primitives/CheatingRecoveryCircuitCreator.hpp"



/** 
* This class represents the second party in the offline phase of Malicious Yao protocol. 
*
* The full protocol specification is described in "Blazing Fast 2PC in the "Offline / Online Setting with Security for
* Malicious Adversaries" paper by Yehuda Lindell and Ben Riva, page 18 - section E, "The Full Protocol Specification".
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar - Ilan University
*
*/
class OfflineProtocolP2 : public Protocol, public Malicious, public TwoParty {

private:
    boost::asio::io_service io_service;

	shared_ptr<ExecutionParameters> mainExecution;			// Parameters of the main circuit.
	shared_ptr<ExecutionParameters> crExecution;			// Parameters of the cheating recovery circuit.
	vector<shared_ptr<CommParty>> channel;							// The channels used communicate between the parties.

	shared_ptr<KProbeResistantMatrix> mainMatrix;			//The probe-resistant matrix used to extend the main circuit's keys.
	shared_ptr<KProbeResistantMatrix> crMatrix;				//The probe-resistant matrix used to extend the cheating recovery circuit's keys.

	shared_ptr<BucketLimitedBundleList> mainBuckets;		//Contain the main circuits.
	shared_ptr<BucketLimitedBundleList> crBuckets;			//Contain the cheating recovery circuits.
	shared_ptr<OTBatchReceiver> maliciousOtReceiver;		//The malicious OT used to transfer the keys.
	bool writeToFile;


	const string HOME_DIR = "../..";
	const string COMM_CONFIG_FILENAME = HOME_DIR + string("/lib/assets/conf/PartiesConfig.txt");
public:
	/**
	* Constructor that sets the parameters.
	* @param mainExecution Parameters of the main circuit.
	* @param crExecution Parameters of the cheating recovery circuit.
	* @param primitives Contains the low level instances to use.
	* @param communication Configuration of communication between parties.
	*/
	OfflineProtocolP2(int argc, char* argv[]);

	~OfflineProtocolP2(){
		io_service.stop();
	}
	/**
	* Runs the second party in the offline phase of the malicious Yao protocol.
	*/
	void run() override {
        runOffline();
    }

    bool hasOffline() override {return true; }
    bool hasOnline() override {return false; }
    void runOffline() override;
    /**
     * Save the buckets and matrices on the disk so the online protocol can read that.
     */
    void saveOnDisk(string bucket_prefix_main, string buckets_prefix_cr, string main_matrix, string cr_matrix){
        mainBuckets->saveToFiles(bucket_prefix_main);
        crBuckets->saveToFiles(buckets_prefix_cr);
        mainMatrix->saveToFile(main_matrix);
        crMatrix->saveToFile(cr_matrix);
    }

	/**
	 * Returns the list of main circuit's buckets.
	 */
	shared_ptr<BucketLimitedBundleList> getMainBuckets() { return this->mainBuckets; }
	/**
	* Returns the list of cheating recovery circuit's buckets.
	*/
	shared_ptr<BucketLimitedBundleList> getCheatingRecoveryBuckets() { return this->crBuckets; }
	/**
	* Returns the probe resistant matrix related to the main circuit.
	*/
	shared_ptr<KProbeResistantMatrix> getMainProbeResistantMatrix() { return this->mainMatrix; }
	/**
	* Returns the probe resistant matrix related to the cheating recovery circuit.
	*/
	shared_ptr<KProbeResistantMatrix> getCheatingRecoveryProbeResistantMatrix() { return this->crMatrix; }

	vector<shared_ptr<CommParty>> getChannel() { return channel; }
	

private:
	/**
	* Returns indices list, from 1 to crInputSizeY.
	* @param crInputSizeY Number of indices to return.
	*/
	vector<int> getSecretSharingLabels(int crInputSizeY);

	/**
	* Creates a probe resistant matrix using the given parameters and sends it to the other party.
	* @param execution Used to get the matrix dimensions.
	* @return the created matrix.
	* @throws IOException
	*/
	shared_ptr<KProbeResistantMatrix> selectAndSendProbeResistantMatrix(shared_ptr<ExecutionParameters> execution);
	/**
	* Creates a probe resistant matrix with n rows and sends it to the other party.
	* @param n Number of rows in the required matrix.
	* @param s statistical parameter.
	* @return the created matrix.
	* @throws IOException If there was a problem in the communication.
	*/
	shared_ptr<KProbeResistantMatrix> selectAndSendProbeResistantMatrix(int n, int s);

	/**
	* Runs the cut and choose protocol using the given parameters.
	* @param execution Parameters of the execution of the main circuit, such as number of checked and eval circuits.
	* @param bundleBuilder Contains the circuit to use.
	* @param inputLabelsY2 The indices of the input labels of Y2.
	* @return The buckets contain the evaluated circuits that generated in the protocol executions.
	* @throws IOException
	* @throws CheatAttemptException
	*/
	shared_ptr<BucketLimitedBundleList> runCutAndChooseProtocol(shared_ptr<ExecutionParameters> execution, 
		shared_ptr<BundleBuilder> bundleBuilder, string garbledTablesFilePrefix, int inputLabelsY2Size = 0);

	/**
	 * Runs the Malicious OT protocol.
	 * @param execution Parameters of the circuit.
	 * @param matrix The matrix that used to extend the keys.
	 * @param buckets contains the circuits.
	 */
	void runObliviousTransferOnP2Keys(shared_ptr<ExecutionParameters> execution, shared_ptr<KProbeResistantMatrix> matrix, 
		shared_ptr<BucketLimitedBundleList> buckets);
};