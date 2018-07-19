#include "../../include/common/CommonMaliciousYao.hpp"


vector<int> circuitGetLabels(GarbledBooleanCircuit* gbc, int party)
{
	//check Integer In Range
	assert((1 <= party) && (party <= 2));
	return gbc->getInputWireIndices(party);
}

void makeRandomBitByteVector(PrgFromOpenSSLAES* prg, vector<byte> & vec)
{
	size_t size = vec.size();

	int byteNum = (size / 8) + 1;
	vector<byte> fromPrg(byteNum);
	prg->getPRGBytes(fromPrg, 0, byteNum);

	bitset<8> bits;
	int idx = 0;
	for (int i = 0; i < byteNum; i++)
	{
		bits = fromPrg[i];
		for (int j = 0; j < 8 && idx < size; j++, idx++)
		{
			if (bits[j] == 0)
				vec[idx] = 0;
			else
				vec[idx] = 1;
		}
	}
}

byte getRandomBit(PrgFromOpenSSLAES* prg)
{
	auto num = prg->getRandom32(); 
	auto bit = num & 1;
	return (byte)bit;
}

vector<byte> readByteVectorFromString(string str, const char separator)
{
	auto fromStr = explode(str, separator);
	size_t numBytes = fromStr.size();
	vector<byte> resVec(numBytes);

	//go over fromStr and set the first char in to resVec as byte
	for (size_t i = 0; i < numBytes; i++) {
		resVec[i] = fromStr[i][0];
	}

	return resVec;
}

vector<long> readLongVectorFromString(string str, const char separator)
{
	auto fromStr = explode(str, separator);
	size_t num = fromStr.size();
	vector<long> resVec(num);

	//go over fromStr and set the first char in to resVec as byte
	for (size_t i = 0; i < num; i++) {
		resVec[i] = std::stol(fromStr[i]);
	}

	return resVec;
}

vector<int> readIntVectorFromString(string str, const char separator)
{
	auto fromStr = explode(str, separator);
	size_t num = fromStr.size();
	vector<int> resVec(num);

	//go over fromStr and set the first char in to resVec as byte
	for (size_t i = 0; i < num; i++) {
		resVec[i] = std::stoi(fromStr[i]);
	}

	return resVec;
}

vector<string> readStringVectorFromString(string str, const char separator)
{
	auto fromStr = explode(str, separator);
	return fromStr;
}

bool equalBlocks(block & a, block & b)
{
	long *ap = (long*)&a;
	long *bp = (long*)&b;
	if ((ap[0] == bp[0]) && (ap[1] == bp[1])) {
		return true;
	}
	return false;
}

bool equalBlocksArray(block * a, block * b, size_t size)
{
	bool flag = true;
	size_t indx = 0;
	while ((indx < size) && (flag))
	{
		flag = equalBlocks(a[indx], b[indx]);
		indx++;
	}

	return flag;
}

vec_block_align convertByteVectorToBlockVectorAligned(vector<byte>& vec)
{
	vec_block_align blocks(vec.size() / SIZE_OF_BLOCK);
	memcpy(&blocks[0], &vec[0], vec.size());

	return blocks;
}

block* convertByteVectorToBlockArray(vector<byte>* vec)
{
	block* blocks = (block *)_mm_malloc(vec->size(), SIZE_OF_BLOCK);
	memcpy((byte*)blocks, vec->data(), vec->size());

	return blocks;
}

vector<byte> convertBlockVectorAligneToByteVector(vec_block_align& vec)
{
	vector<byte> bytes(vec.size() * 16);
	memcpy(&bytes[0], &vec[0], bytes.size());
	return bytes;
}

vector<byte> convertBlockArrayToByteVector(block* vec, int size)
{
	vector<byte> bytes(size * 16);
	memcpy(&bytes[0], (byte*)vec, bytes.size());
	return bytes;
}

void makeByteVectorFromBlockVector(vec_block_align& vec, vector<byte> & toRet)
{
	byte* tmp = (byte*)&vec[0];
	size_t byteNumtmp = vec.size() * 16;

	toRet.assign(tmp,tmp+byteNumtmp);
}

//vector<byte> readFileToBuffer(const string& fileName)
//{
//	std::ifstream is(fileName.c_str(), std::ifstream::ate | std::ifstream::binary);
//
//	// get length of file:
//	auto length = static_cast<std::vector<byte>::size_type>(is.tellg());
//	//go to begining
//	is = std::ifstream(fileName.c_str(), std::ios::binary);
//	if (is) {
//		vector<byte> buffer(length);
//		// read data as a block:
//		is.read((char*)&buffer[0], length);
//
//		return buffer;
//	}
//	return vector<byte>();
//}
//
//void writeToFileFromBuffer(vector<byte>& buffer, const string& fileName)
//{
//	std::ofstream outfile(fileName.c_str(), std::ios::binary | ios::out | ios::trunc);
//	int count = 0;
//	while (!outfile && count < NUMBER_OPEN_TRY)
//	{
//		outfile.open(TEMP_FILE, std::ios::binary);
//	}
//
//	// write to outfile
//	outfile.write((char*)&buffer[0], buffer.size());
//
//	outfile.close();
//}

