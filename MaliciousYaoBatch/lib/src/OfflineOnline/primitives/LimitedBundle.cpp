#include "../../../include/OfflineOnline/primitives/LimitedBundle.hpp"

tuple<vector<byte>, block*> LimitedBundle::getGarbledTablesFromFile() const
{
	//read outputWires to vector<byte> align to 16 with no destractor
	vector<byte, aligned_allocator_no_destructor<byte, SIZE_OF_BLOCK>> readGarbledTables;
	{
		//read file and set obj
		ifstream ifs(this->tablesFile.c_str(), ifstream::binary);
		boost::archive::binary_iarchive ia(ifs);

		ia >> readGarbledTables;
	}

	//convert from vector<byte> to block*
	block* garbledTablesNew = (block*)&readGarbledTables[0];
	size_t byteNum = readGarbledTables.size();
	byte* temp = (byte*)garbledTablesNew;

	//make byte vector of block*
	vector<byte> garbledTablesToSend(temp, temp + byteNum);

	return make_tuple(garbledTablesToSend, garbledTablesNew);
}

LimitedBundle::LimitedBundle(block* garbledTables, size_t garbledTableSize, vector<byte> & translationTable, size_t inputLabelsXSize, size_t labelsY2Size, size_t outputLabelsSize,
	const shared_ptr<CommitmentBundle> & commitmentsX, const shared_ptr<CommitmentBundle> & commitmentsY1Extended, 
	const shared_ptr<CommitmentBundle> & commitmentsY2, CmtCCommitmentMsg * commitmentsOutput, const shared_ptr<CmtCDecommitmentMessage> & decommitmentsOutput, 
	const shared_ptr<DifferenceCommitmentReceiverBundle> & diffCommitments, string& tablesFile)
{
	this->garbledTableSize = garbledTableSize;
	this->garbledTables = garbledTables;
	this->translationTable = translationTable;

	this->labelsXSize = inputLabelsXSize;
	this->outputLabelsSize = outputLabelsSize;
	this->labelsY2Size = labelsY2Size;

	this->commitmentsX = commitmentsX;
	this->commitmentsY1Extended = commitmentsY1Extended;
	this->commitmentsY2 = commitmentsY2;

	this->commitmentsOutput = std::static_pointer_cast<vector<byte>>(commitmentsOutput->getCommitment());
	this->commitmentsOutputId = commitmentsOutput->getId();
	this->decommitmentsOutput = decommitmentsOutput;
	this->diffCommitments = diffCommitments;

	this->tablesFile = tablesFile;
}

LimitedBundle::~LimitedBundle()
{
	//In case the bundle is created in the online phase, the garbles tables are used to set the circuit. Then, the circuit takes responsability and deletes the tables.
	if (garbledTables != nullptr) {
		_mm_free(garbledTables);
		garbledTables = nullptr;
	}
}
