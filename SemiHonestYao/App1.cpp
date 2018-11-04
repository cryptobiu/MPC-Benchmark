/**
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
* Copyright (c) 2016 LIBSCAPI (http://crypto.biu.ac.il/SCAPI)
* This file is part of the SCAPI project.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
* 
* Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
* to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
* and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
* 
* The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
* 
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
* FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
* 
* We request that any publication and/or code referring to and/or based on SCAPI contain an appropriate citation to SCAPI, including a reference to
* http://crypto.biu.ac.il/SCAPI.
* 
* Libscapi uses several open source libraries. Please see these projects for any further licensing issues.
* For more information , See https://github.com/cryptobiu/libscapi/blob/master/LICENSE.MD
*
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
*/


#include "YaoParties.hpp"
#include "../../include/infra/CircuitConverter.hpp"

void execute_party_one(PartyOne* p1) {
	
	auto all = scapi_now();

    int numIterations = p1->getConfig().number_of_iterations;
	// run Party one
	p1->run();

	auto end = std::chrono::system_clock::now();
	int elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - all).count();
	cout << "********************* PartyOne ********\nRunning " << numIterations <<
		" iterations took: " << elapsed_ms << " milliseconds" << endl
		<< "Average time per iteration: " << elapsed_ms / (float)numIterations << " milliseconds" << endl;

}

void execute_party_two(PartyTwo* p2) {
	
	auto all = scapi_now();

    int numIterations = p2->getConfig().number_of_iterations;

	// run party two of Yao protocol.
	p2->run();

	auto end = std::chrono::system_clock::now();
	int elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - all).count();
	cout << "********************* PartyTwo ********\nRunning " << numIterations <<
		" iterations took: " << elapsed_ms << " milliseconds" << endl;
	cout << "Average time per iteration: " << elapsed_ms / (float)numIterations
		<< " milliseconds" << endl;

}

YaoConfig read_yao_config(string config_file) {
#ifdef _WIN32
	string os = "Windows";
#else
	string os = "Linux";
#endif
	ConfigFile cf(config_file);
	int number_of_iterations = stoi(cf.Value("", "number_of_iterations"));
	string str_print_output = cf.Value("", "print_output");
	bool print_output;
	istringstream(str_print_output) >> std::boolalpha >> print_output;
	string input_section = cf.Value("", "input_section") + "-" + os;
	string circuit_file = cf.Value(input_section, "circuit_file");
	string input_file_1 = cf.Value(input_section, "input_file_party_1");
	string input_file_2 = cf.Value(input_section, "input_file_party_2");
	string sender_ip_str = cf.Value("", "sender_ip");
	string receiver_ip_str = cf.Value("", "receiver_ip");
	int sender_port_str = stoi(cf.Value("", "sender_port"));
	int receiver_port_str = stoi(cf.Value("", "receiver_port"));
	string circuit_type = cf.Value("", "circuit_type");
	return YaoConfig(number_of_iterations, print_output, circuit_file, input_file_1,
		input_file_2, sender_ip_str, sender_port_str, receiver_ip_str, receiver_port_str, circuit_type);
}

int main(int argc, char* argv[]) {

    CmdParser parser;
    auto parameters = parser.parseArguments("",argc, argv);
    int partyNum = stoi(parser.getValueByKey(parameters, "partyID"));


	if (partyNum == 0) {
		// create Party one with the previous created objects.
		PartyOne p1(argc, argv);
		execute_party_one(&p1);
	}
	else if (partyNum == 1) {
		PartyTwo p2(argc, argv);
		execute_party_two(&p2);
		auto output = p2.getOutput();
	} else {
		std::cerr << "Usage: libscapi_examples yao <party_number(0|1)> <config_path>" << std::endl;
		return 1;
	}

	return 0;
}

