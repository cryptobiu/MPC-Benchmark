#pragma once

#include "../../../include/common/CommonMaliciousYao.hpp"
#include "../../../include/OfflineOnline/primitives/LimitedBundle.hpp"

/*
Class BucketLimitedBundle save all the bundle the belongs in one bucket
*/
class BucketLimitedBundle {
private:
	vector<shared_ptr<LimitedBundle>> bucket;		//save all the LimitedBundles

public:
	/*
	Init Bucket
	*/
	BucketLimitedBundle() {}

	vector<shared_ptr<LimitedBundle>> getAllLimitedBundles() { return this->bucket; }
	int size() { return bucket.size(); }

	shared_ptr<LimitedBundle> getLimitedBundleAt(size_t index) { return this->bucket[index]; }

	void addLimitedBundle(shared_ptr<LimitedBundle> b) {
		this->bucket.push_back(b);
	}

	friend class boost::serialization::access;
	template<class Archive>
	void serialize(Archive & ar, const unsigned int version)
	{
		ar & bucket;
	}
};
