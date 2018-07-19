#include "../../include/CommitmentWithZkProofOfDifference/SC.hpp"

SC::SC(PrgFromOpenSSLAES* prg, vector<byte>& x, long id, int sNew)
{
	//Set the parameters.
	this->n = x.size();
	this->s = sNew;
	this->commitmentId = id;

	//Allocate space for the random values and commitments.
	this->r = vector<shared_ptr<vector<byte>>>(s);
	this->commitments = vector<SCom>(s);

	
	//Create each commitment pair, s times.
	for (int i = 0; i < s; i++) {
		//generate random string.
		this->r[i] = make_shared<vector<byte>>(n);
		makeRandomBitByteVector(CryptoPrimitives::getRandom().get(), *r[i]);
		//Create pair of commitments.
		this->commitments[i] = SCom(prg, x, *r[i].get(), this->commitmentId);
		//Increase the id by 2, since two commitments were already created.
		this->commitmentId += 2;
	}

}

vector<vector<byte>> SC::getCommitments()
{
	//Create a long array of commitments.
	vector<vector<byte>> messages(s * 2);

	//Get each pair of commitments and put the commitments in the big array.
	for (int i = 0; i < s; i++) {
		messages[2 * i] = this->commitments[i].getC0();
		messages[2 * i + 1] = this->commitments[i].getC1();
	}

	return messages;
}

vector<vector<byte>> SC::getDecommitmentsX()
{
	//Create a long array of decommitments.
	vector<vector<byte>> messages(this->s * 2);

	//Get each pair of decommitments and put the decommitments in the big array.
	for (int i = 0; i < s; i++) {
		messages[2 * i] = this->commitments[i].getDecomX(0);
		messages[2 * i + 1] = this->commitments[i].getDecomX(1);
	}

	return messages;
}

vector<vector<byte>> SC::getDecommitmentsR()
{
	//Create a long array of decommitments.
	vector<vector<byte>> messages(this->s * 2);

	//Get each pair of decommitments and put the decommitments in the big array.
	for (int i = 0; i < s; i++) {
		messages[2 * i] = this->commitments[i].getDecomR(0);
		messages[2 * i + 1] = this->commitments[i].getDecomR(1);
	}

	return messages;
}

vector<byte> SC::getR()
{
	//Allocate enough space for all random values.
	size_t size = r[0].get()->size();
	vector<byte> allR(r.size()*size);

	//Copy each random value to the big array.
	size_t row = r.size();
	size_t countNum = 0;
	for (size_t i = 0; i < row; i++) {
		std::copy_n(this->r[i].get()->begin(), size, &allR[countNum]);
		countNum += size;
	}

	return allR;
}

