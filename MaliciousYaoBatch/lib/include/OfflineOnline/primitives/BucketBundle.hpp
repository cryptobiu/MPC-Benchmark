#pragma once

#include "../../../include/common/CommonMaliciousYao.hpp"
#include "../../../include/OfflineOnline/primitives/Bundle.hpp"

/*
 Class BucketBundle save all the bundle the belongs in one bucket
*/
class BucketBundle {
private:
	vector<shared_ptr<Bundle>> bucket;		//save all the bundles

public:
	/*
	 Init Bucket
	*/
	BucketBundle() {}

	vector<shared_ptr<Bundle>> getAllBundles() { return this->bucket; }
	size_t size() { return bucket.size(); }

	shared_ptr<Bundle> getBundleAt(size_t index) { return this->bucket[index]; }

	void addBundle(shared_ptr<Bundle> b) { 
		this->bucket.push_back(b);
	}

	friend class boost::serialization::access;
	template<class Archive>
	void serialize(Archive & ar, const unsigned int version)
	{
		ar & bucket;
	}
};
