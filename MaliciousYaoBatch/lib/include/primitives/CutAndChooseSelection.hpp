#pragma once

#include "../../include/common/CommonMaliciousYao.hpp"

/**
* This class holds the selection of the Cut-And-Choose protocol:
* 1. The number of circuit to check
* 2. The number of circuits to evaluate.
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University 
*
*/
class CutAndChooseSelection {
private:
	vector<byte> selection;				//The array that defines which circuit selected to be checked and which to evaluate.
										//If the index of the circuit contain "1" than this circuit should be checked. 
										//Otherwise, the circuit should be evaluated.
	size_t numCircuits;					//The total circuits number.
	vector<size_t> checkCircuits;			//The indices of the checked circuits.
	vector<size_t> evalCircuits;			//The indices of the evaluated circuits.

public:
	/**
	* A constructor that gets the array that defines which circuit selected to be checked and which to
	* evaluate and set the inner members accordingly.
	* Get number of circuit that are chacked.
	*/
	CutAndChooseSelection(vector<byte>& selection, int numCheck) { doConstruct(selection, numCheck); }

	/**
	* A constructor that gets the array that defines which circuit selected to be checked and which to
	* evaluate and set the inner members accordingly.
	*/
	CutAndChooseSelection(vector<byte>& selection);

	void doConstruct(vector<byte>& selection, int numCheck);

	/**
	* returns the selection array that defines which circuit selected to be checked and which to evaluate..
	*/
	vector<byte> asByteArray() { return selection; }

	/**
	* Return the set of checked circuits.
	*/
	vector<size_t> getCheckCircuits() { return checkCircuits; }

	/**
	* Return the set of evaluated circuits.
	*/
	vector<size_t> getEvalCircuits() { return evalCircuits; }
};