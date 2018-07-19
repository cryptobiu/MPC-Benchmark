#pragma once

#include <libscapi/include/circuits/GarbledBooleanCircuit.h>
#include <libscapi/include/circuits/BooleanCircuits.hpp>
#include <math.h>

using namespace std;

/**
 This class manages the parameters needed by the execution.

 These parameters contain the garbled circuit and boolean circuit used in the protocol, as well as
 protocol parameters described in "Blazing Fast 2PC in the "Offline/Online Setting with Security for
 Malicious Adversaries" paper by Yehuda Lindell and Ben Riva, section 2.4 [Cut-and-Choose Parameters].

 This class contains also the number of evaluated and checked circuits and more.
*/
class ExecutionParameters
{
private:
	shared_ptr<BooleanCircuit> bc;
	vector<shared_ptr<GarbledBooleanCircuit>> gbc;		// The boolean circuit to evaluate in the protocol.

	int numExecutions;				// N
	int statisticalParameter;		// s
	int bucketSize;					// B
	double evaluationProbability;	// p

	int numCircuits;				// N * B
	int evalCircuits;				// N * B / p
	int checkCircuits;				// N * B / p -  N * B

public:
	ExecutionParameters(){}
	/*
	 Constructor that sets the parameters.
	*/
	ExecutionParameters(const shared_ptr<BooleanCircuit> & bc, vector<shared_ptr<GarbledBooleanCircuit>> & mainGbc,
		int numExecutions, int statisticalParameter, int bucketSize, double evaluationProbability)	{
		this->bc = bc;
		this->gbc = mainGbc;
		this->numExecutions = numExecutions;	//N
		this->statisticalParameter = statisticalParameter;	//s
		this->bucketSize = bucketSize;	//B
		this->evaluationProbability = evaluationProbability; //P

		this->evalCircuits = numExecutions * bucketSize;
		this->numCircuits = ceil(evalCircuits / evaluationProbability);
		this->checkCircuits = numCircuits - evalCircuits;
	}

	/*
	 Getters
	*/
	shared_ptr<BooleanCircuit> getBooleanCircuit() { return bc; }
	shared_ptr<GarbledBooleanCircuit> getCircuit(int i) { return this->gbc[i]; }
	vector<shared_ptr<GarbledBooleanCircuit>> getCircuits() { return this->gbc; }
	int getNumberOfExecutions() { return this->numExecutions; }
	int getBucketSize() { return this->bucketSize; }
	double getEvaluationProbability() { return this->evaluationProbability; }
	int getNumCircuits() { return this->numCircuits; }
	int getEvalCircuits() { return this->evalCircuits; }
	int getCheckCircuits() { return this->checkCircuits; }
	int getStatisticalParameter() { return this->statisticalParameter;  }
	};
