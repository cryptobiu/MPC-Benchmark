#include "../../include/primitives/CircuitInput.hpp"

/**
A constructor that sets the given input for the given wires.
input:
inputBits The input for each wire.
wireLabels The indices of the wires.
*/
CircuitInput::CircuitInput(const shared_ptr<vector<byte>> & inputBits)
{
	// check input is correct
	assert(inputBits->size() != 0);

	this->input = inputBits;
	// check that all the bits are 0 or 1
	for (const auto& b : *inputBits) {
		//check binary
		assert((0 <= b) && (b <= 1));
	}

}


/**
 Alternative constructor.
 It creates new CircuitInput object and read the input from the given file.
 input:
		filename The name of the file to read the inputs from.
		bc The circuit to get the inputs for.
		party the party number which the inputs belongs.
 return:
		the created CircuitInput object.
*/
shared_ptr<CircuitInput> CircuitInput::fromFile(string filename, int inputsNumber)
{
	auto sc = scannerpp::Scanner(new scannerpp::File(filename));
	auto inputVector = make_shared<vector<byte>>(inputsNumber);
	for (int i = 0; i < inputsNumber; i++)
		inputVector->at(i) = (byte)sc.nextInt();

	return make_shared<CircuitInput>(inputVector);
}

/**
 Alternative constructor.
 It creates new CircuitInput object and sets random inputs.
 Inputs:
		labels The indices of the wires.
		 random maker.
 Return:
		the created CircuitInput object.
*/
shared_ptr<CircuitInput> CircuitInput::randomInput(size_t sizeCircuit, PrgFromOpenSSLAES* mt)
{
	vector<byte> tmp(sizeCircuit);
	makeRandomBitByteVector(mt, tmp);
	return make_shared<CircuitInput>(CircuitInput(make_shared<vector<byte>>(tmp)));
}

/**
Alternative constructor.
It creates new CircuitInput object and sets the inputs from the given key.
Inputs:
inputKey The key that used to get the inputs.
Return:
the created CircuitInput object.
*/
shared_ptr<CircuitInput> CircuitInput::fromSecretKey(SecretKey & inputKey)
{
	auto temp = inputKey.getEncoded();
	shared_ptr<vector<byte>> inputBinaryArray = BinaryUtils::getBinaryByteArray(temp);

	//Create a new CircuitInput object from the inputs and indices arrays and return it.
	return make_shared<CircuitInput>(inputBinaryArray);
}


/**
Returns the xor of the inputs in the two given CircuitInputs objects.
Inputs:
	x1 The first input to xor with the other.
	x2 The second input to xor with the other.
Return:
	the xor result.
*/
vector<byte> CircuitInput:: xorCircuits (const CircuitInput* x1,const CircuitInput* x2)
{
	//Check if the sizes of inputs are equal.
	assert(x1->size() == x2->size());

	size_t sizeCir = x1->size();
	vector<byte> vec1 = *x1->getInputVectorShared();
	vector<byte> vec2 = *x2->getInputVectorShared();
	vector<byte> res(sizeCir);

	// Xor the inputs arrays.
	for (size_t i = 0 ; i < sizeCir ; i++) {
		res[i] = vec1[i] ^ vec2[i];
	}

	return res;
}
