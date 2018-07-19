#include "../../../include/OfflineOnline/primitives/BucketLimitedBundleList.hpp"

BucketLimitedBundleList::BucketLimitedBundleList(shared_ptr<ExecutionParameters> execution, shared_ptr<BucketMapping> bucketMapping)
{
	int numBuckets = execution->getNumberOfExecutions();
	this->bucketMapping = bucketMapping;

	//Create the arrays of the buckets.
	this->buckets = vector<shared_ptr<BucketLimitedBundle>>(numBuckets);
	for (int i = 0; i < numBuckets; i++) {
		this->buckets[i] = make_shared<BucketLimitedBundle>();
	}
}

void BucketLimitedBundleList::add(shared_ptr<LimitedBundle> LimitedBundle, size_t index)
{
	//Get the id of the bucket where the item should be placed.
	int bucketId = bucketMapping->bucketOf(index);

	//Put the item in the right bucket.
	this->buckets[bucketId]->addLimitedBundle(LimitedBundle);
}

shared_ptr<BucketLimitedBundle> BucketLimitedBundleList::getBucket(size_t bucketId)
{
	assert((0 <= bucketId) && (bucketId <= buckets.size()));
	return this->buckets[bucketId];
}

shared_ptr<LimitedBundle> BucketLimitedBundleList::getLimitedBundle(int bucketId, int itemId)
{
	assert((0 <= bucketId) && (bucketId <= buckets.size()));
	assert((0 <= itemId) && (itemId <= buckets[bucketId]->size()));
	return this->buckets[bucketId]->getLimitedBundleAt(itemId);
}

void BucketLimitedBundleList::saveToFiles(string prefix)
{
	//For each bucket, create a file and write the bucket.
	size_t numBuckets = buckets.size();
	for (size_t j = 0; j < numBuckets; j++) {
		boost::format formatter("%1%.%2%.cbundle");
		formatter % prefix;
		formatter % j;
		string filename = formatter.str();

		//new scope because BinaryOutputArchive flash in distractor
		{
			//write to binary file
			std::ofstream os(filename, ios::binary);
			boost::archive::binary_oarchive oa(os);
			oa.template register_type<CmtSimpleHashCommitmentMessage>();
			oa.template register_type<CmtSimpleHashDecommitmentMessage>();

			oa & buckets[j];
		}
	}
}

shared_ptr<BucketLimitedBundle> BucketLimitedBundleList::loadBucketFromFile(string filename)
{
	//read from file
	shared_ptr<BucketLimitedBundle> bucket;
	ifstream ifs(filename.c_str(), ios::binary);
	boost::archive::binary_iarchive ia(ifs);
	ia.template register_type<CmtSimpleHashCommitmentMessage>();
	ia.template register_type<CmtSimpleHashDecommitmentMessage>();
	ia & bucket;


	return bucket;
}
