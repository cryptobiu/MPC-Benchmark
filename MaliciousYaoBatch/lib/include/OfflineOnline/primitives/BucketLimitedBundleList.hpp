#pragma once

#include <boost/format.hpp>
#include "../../../include/common/CommonMaliciousYao.hpp"
#include "../../../include/OfflineOnline/primitives/BucketLimitedBundle.hpp"
#include "../../../include/OfflineOnline/primitives/BucketMapping.hpp"
#include "../../../include/primitives/ExecutionParameters.hpp"

/*
Class BucketLimitedBundleList holds vector of buckets each consists of LimitedBundle.
*/
class BucketLimitedBundleList {
private:
	shared_ptr<BucketMapping> bucketMapping;	// An object that maps a LimitedBundle into the right bucket.
	vector<shared_ptr<BucketLimitedBundle>> buckets;		// Arrays that stores all LimitedBundles.

public:

	BucketLimitedBundleList() {}

	/**
	* A constructor that initializes the list using the given execution parameters and bucketMapping.
	* @param execution contains the number of buckets and bucket size.
	* @param bucketMapping An object that maps a LimitedBundle into the right bucket.
	*/
	BucketLimitedBundleList(shared_ptr<ExecutionParameters> execution, shared_ptr<BucketMapping> bucketMapping);

	/**
	* Adds the given item to the list.
	* @param item To add to the list.
	* @param index The index that the item should be placed at.
	*/
	void add(shared_ptr<LimitedBundle> LimitedBundle, size_t index);

	/**
	* Returns the number of buckets in the list.
	*/
	size_t size() { return buckets.size(); }

	/**
	* Returns the bucket according to the given id.
	* @param bucketId The id of the requested bucket.
	*/
	shared_ptr<BucketLimitedBundle> getBucket(size_t bucketId);

	/**
	* Returns the LimitedBundle according to the given item and bucket ids.
	* @param bucketId The id of the bucket where the item is placed.
	* @param itemId The id of the requested item.
	*/
	shared_ptr<LimitedBundle> getLimitedBundle(int bucketId, int itemId);

	/**
	* Prints the buckets to files. Each bucket is printed to a different file.
	* @param prefix The prefix of the files names.
	* @throws FileNotFoundException
	* @throws IOException
	*/
	void saveToFiles(string prefix);

	/**
	* Loads a bucket of LimitedBundles from a file. (This actually reads one bucket in each function call).
	* @param filename The name of the file to read from.
	* @return The created array filled with items.
	* @throws FileNotFoundException
	* @throws IOException
	*/
	static shared_ptr<BucketLimitedBundle> loadBucketFromFile(string filename);

};