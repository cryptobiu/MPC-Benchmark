#pragma once
#include <string>
#include <chrono>
#include <iostream>
using namespace std;

/**
* This class provides a tool to measure times.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
*
*/
class LogTimer {
private:
	chrono::high_resolution_clock::time_point start;				// Used to hold the start time of some action.
	chrono::high_resolution_clock::time_point end;				// Used to hold the end time of some action.
	string name;			// Holds the name of the measured action. 
	bool verbose;	//Indicates whether or not print the times.

public:

	/**
	* Starts the timer.
	* @param name The name of the started action.
	* @param verbose Indicates whetstarther or not print the times.
	*/
	LogTimer(string name, bool verbose = true) {
		reset(name);
		this->verbose = verbose;
	}

	/**
	* Restarts the timer.
	* @param name  The name of the restarted action.
	*/
	void reset(string name) {
		this->name = name;
		start = chrono::high_resolution_clock::now();
		if (verbose) {
			cout << "started " << name << "..." << endl;
		}
	}

	/**
	* Stops the timer.
	*/
	void stop() {
		end = chrono::high_resolution_clock::now();
		auto runtime = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
		if (verbose) {
			cout << name << " took " << runtime << " milliseconds." << endl;
			cout << "--------------------------------------------------------------------------------" << endl;
		}
	}
};

