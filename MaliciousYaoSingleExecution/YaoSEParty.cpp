//
// Created by moriya on 15/2/17.
//
#ifndef _WIN32

#include "YaoSEParty.h"

CircuitFile *cf;
void compute(Bit * res, Bit * in, Bit * in2) {
    cf->compute((block*)res, (block*)in, (block*)in2);
}

YaoSEParty::YaoSEParty(int argc, char* argv[]) : Protocol("MaliciousYaoSingleExecution", argc, argv){

    id = stoi(arguments["partyID"]);
    CircuitConverter::convertScapiToBristol(arguments["circuitFile"], "emp_format_circuit.txt", false);

    string inputFile = arguments["inputFile"];
    timer = new Measurement("MaliciousYaoSingleExecution", id, 2, times);
    times = stoi(arguments["internalIterationsNumber"]);
    //open file
    ConfigFile config(arguments["partiesFile"]);
    cout << "After parties file" << endl;

    string portString = "party_1_port";
    string ipString = "party_1_ip";
    int port;
    string ip;


    //get partys IPs and ports data
    port = stoi(config.Value("", portString));
    cout << "After parties port" << endl;
    ip = config.Value("", ipString);
    cout << "After parties ip" << endl;


    io = new NetIO(id==0 ? nullptr:ip.c_str(), port);
    cf = new CircuitFile("emp_format_circuit.txt");
    if(id == 0) {
        input = new bool[cf->n1];
        readInputs(inputFile, input, cf->n1);
    } else {
        input = new bool[cf->n2];
        readInputs(inputFile, input, cf->n2);
    }

    out = new bool[cf->n3];
    mal = new Malicious2PC <>(io, id + 1, cf->n1, cf->n2, cf->n3);
}

void YaoSEParty::readInputs(string inputFile, bool * inputs, int size){
    //Read the input from the given input file
    ifstream myfile;
    int input;

    myfile.open(inputFile);
    for (int i = 0; i<size; i++){
        myfile >> input;
        inputs[i] = (bool) input;
    }
    myfile.close();
}

/*
 * Implement the function derived from the Protocol abstract class.
 */
void YaoSEParty::run() {
    vector<string> subTaskNames{"Run"};
    timer->setTaskNames(subTaskNames);
    void * f = (void *)&compute;
    for (currentIteration = 0; currentIteration<times; currentIteration++) {
        timer->startSubTask(0, currentIteration);
        if (id == 0) {
            mal->alice_run(f, input);
        } else {
            mal->bob_run(f, input, out);
        }
        timer->endSubTask(0, currentIteration);
    }
}

void YaoSEParty::runOffline(){
    vector<string> subTaskNames{"Offline", "Online"};
    timer->setTaskNames(subTaskNames);

    void * f = (void *)&compute;
    timer->startSubTask(0, currentIteration);
    if (id == 0) {
        mal->alice_offline(f);

    } else {
        mal->bob_offline(f);
    }
    timer->endSubTask(0, currentIteration);
}

void YaoSEParty::sync(){
    io->sync();
}

void YaoSEParty::preOnline() {
    if (id == 1) {
        mal->bob_preload();
    }
}

void YaoSEParty::runOnline(){
    void * f = (void *)&compute;

    timer->startSubTask(1, currentIteration);
    if (id == 0) {
        mal->alice_online(f, input);
    } else {
        mal->bob_online(f, input, out);
    }
    timer->endSubTask(1, currentIteration);
}

#endif
