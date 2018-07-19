#include "../../../include/OfflineOnline/primitives/BucketMapping.hpp"

BucketMapping::BucketMapping(vector<size_t> circuits, int numBuckets, int bucketSize, vector<byte>& seed) {
	//Check that the number of circuit equals to numBuckets * bucketSize.
	assert(circuits.size() == numBuckets * bucketSize);

	//Create a new array that contains the circuits, then shuffle it.
	this->shuffledCircuits = circuits;
	
	auto prg = SeededRandomnessProvider::getSeededSecureRandom(seed);
	//shuffle
	auto size = shuffledCircuits.size();
	for (size_t i = size - 1; i > 0; i--) {
		int index = prg->getRandom32() % size;
		auto tmp = shuffledCircuits[i];
		shuffledCircuits[i] = shuffledCircuits[index];
		shuffledCircuits[index] = tmp;
	}

	//init buckets
	this->buckets = vector<shared_ptr<vector<size_t>>>(numBuckets);
	this->mapping = map<int, int>();
	//Put in the buckets arrays and the mapping map the indices of the shuffled circuits.
	//The indices are taken from the shufflesCircuits array.
	for (int bucketIndex = 0; bucketIndex < numBuckets; bucketIndex++) {
		this->buckets[bucketIndex] = make_shared<vector<size_t>>(bucketSize);
		for (int i = 0; i < bucketSize; i++) {
			size_t circuit = shuffledCircuits[bucketIndex * bucketSize + i];
			this->buckets[bucketIndex]->at(i) = circuit;
			this->mapping[circuit] = bucketIndex;
		}
	}
}

int BucketMapping::bucketOf(size_t circuitId)
{
	//check that circuitId exist
	assert(std::find(shuffledCircuits.begin(), shuffledCircuits.end(), circuitId) != shuffledCircuits.end());
	return mapping[circuitId];
}
