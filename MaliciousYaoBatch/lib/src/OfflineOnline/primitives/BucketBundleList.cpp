#include "../../../include/OfflineOnline/primitives/BucketBundleList.hpp"

BucketBundleList::BucketBundleList(shared_ptr<ExecutionParameters> execution, shared_ptr<BucketMapping> bucketMapping)
{
	int numBuckets = execution->getNumberOfExecutions();
	int bucketSize = execution->getBucketSize();
	this->bucketMapping = bucketMapping;

	//Create the arrays of the buckets.
	this->buckets = vector<shared_ptr<BucketBundle>>(numBuckets);
	for (int i = 0; i < numBuckets; i++) {
		this->buckets[i] = make_shared<BucketBundle>();
	}
}

void BucketBundleList::add(shared_ptr<Bundle> bundle, size_t index)
{
	//Get the id of the bucket where the item should be placed.
	int bucketId = bucketMapping->bucketOf(index);

	//Put the item in the right bucket.
	this->buckets[bucketId]->addBundle(bundle);
}

shared_ptr<BucketBundle> BucketBundleList::getBucket(size_t bucketId)
{
	assert((0 <= bucketId) && (bucketId <= buckets.size()));
	return this->buckets[bucketId];
}

shared_ptr<Bundle> BucketBundleList::getBundle(int bucketId, int itemId)
{
	assert((0 <= bucketId) && (bucketId <= buckets.size()));
	assert((0 <= itemId) && (itemId <= buckets[bucketId]->size()));
	return this->buckets[bucketId]->getBundleAt(itemId);
}

void BucketBundleList::saveToFiles(string prefix)
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
			std::ofstream os(filename, std::ios::binary);
			boost::archive::binary_oarchive oa(os);
			oa.template register_type<CmtSimpleHashCommitmentMessage>();
			oa.template register_type<CmtSimpleHashDecommitmentMessage>();
			oa << buckets[j];
		}
	}
}

shared_ptr<BucketBundle> BucketBundleList::loadBucketFromFile(string filename)
{
	//read from file
	shared_ptr<BucketBundle> bucket;
	ifstream ifs(filename.c_str(), std::ios::binary);
	boost::archive::binary_iarchive ia(ifs);
	ia.template register_type<CmtSimpleHashCommitmentMessage>();
	ia.template register_type<CmtSimpleHashDecommitmentMessage>();
	ia >> bucket;


	return bucket;
}
