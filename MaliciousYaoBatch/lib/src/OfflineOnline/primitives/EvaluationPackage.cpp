#include "../../../include/OfflineOnline/primitives/EvaluationPackage.hpp"
/**
* Returns Decommitment to Y2 input keys, according to the given circuit id and the index.
* @param circuitId The circuit that the requested decommitment belongs.
* @param index The index of the y2 input wire that the decommitment belongs.
* @param numWires number of input wires.
* @param keySize The size of each key, in bytes.
* @param hashSize The size of the decommitment, in bytes.
*/
/*CmtSimpleHashDecommitmentMessage EvaluationPackage::getDecommitmentToY2InputKey(int circuitId, size_t index, size_t numWires, int keySize, int hashSize) {
	vector<byte> x(keySize);
	memcpy(x.data(), decommitmentsY2InputKeysX.data() + keySize*(circuitId*numWires + index), keySize);
	vector<byte> r(hashSize);
	memcpy(r.data(), decommitmentsY2InputKeysR.data() + hashSize*(circuitId*numWires + index), hashSize);

	return CmtSimpleHashDecommitmentMessage(make_shared<ByteArrayRandomValue>(r), make_shared<vector<byte>>(x));
}*/

/**
* Returns Decommitment to X input keys, according to the given circuit id and the index.
* @param circuitId The circuit that the requested decommitment belongs.
* @param index The index of the x input wire that the decommitment belongs.
* @param numWires number of input wires.
* @param keySize The size of each key, in bytes.
* @param hashSize The size of the decommitment, in bytes.
*/
/*CmtSimpleHashDecommitmentMessage EvaluationPackage::getDecommitmentToXInputKey(size_t circuitId, size_t index, size_t numWires, int keySize, int hashSize) {
	vector<byte> x(keySize);
	memcpy(x.data(), decommitmentsXInputKeysX.data() + keySize*(circuitId* numWires + index), keySize);
	vector<byte> r(hashSize);
	memcpy(r.data(), decommitmentsXInputKeysR.data() + hashSize*(circuitId*numWires + index), hashSize);

	return CmtSimpleHashDecommitmentMessage(make_shared<ByteArrayRandomValue>(r), make_shared<vector<byte>>(x));
}*/

/**
* Returns Decommitment to output key, according to the given circuit id.
* @param circuitId The circuit that the requested decommitment belongs.
* @param numWires number of output wires.
* @param keySize The size of each key, in bytes.
* @param hashSize The size of the decommitment, in bytes.
*/
/*CmtSimpleHashDecommitmentMessage EvaluationPackage::getDecommitmentToOutputKey(size_t circuitId, size_t numWires, int keySize, int hashSize) {
	vector<byte> x(keySize * 2 * numWires);
	memcpy(x.data(), decommitmentsOutputKeysX.data() + keySize*circuitId*numWires * 2, keySize * 2 * numWires);
	vector<byte> r(hashSize);
	memcpy(r.data(), decommitmentsOutputKeysR.data() + hashSize*circuitId, hashSize);

	return CmtSimpleHashDecommitmentMessage(make_shared<ByteArrayRandomValue>(r), make_shared<vector<byte>>(x));
}*/

/**
* Returns the xored proof, according to the given circuit id, index and sigma.
* @param wireIndex The index of the wire that the proof belongs.
* @param circuitId The circuit that the requested proof belongs.
* @param sigma Indicates which proof to return (there are two proofs for each wire.)
* @param numCircuits number of circuits.
* @param keySize The size of each key, in bytes.
*/
block EvaluationPackage::getXoredProof(size_t wireIndex, size_t circuitId, int sigma, size_t numCircuits, int keySize) {
	block proof;
	memcpy(&proof, xoredProofOfCheating.data() + keySize*(wireIndex*numCircuits * 2 + circuitId * 2 + sigma), keySize);
	return proof;
}