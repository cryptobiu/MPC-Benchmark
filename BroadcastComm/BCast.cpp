//
// Created by moriya on 04/01/17.
//

#include "BCast.h"

using namespace std;

BCast::BCast(int argc, char* argv []): MPCProtocol("BCast", argc, argv) {

    vector<string> names{"TestComm"};
    timer->addTaskNames(names);

    m_d = stoi(getParser().getValueByKey(arguments, "D"));

    // generate data
    createData();

}



void BCast::createData()
{
    random_bytes_engine rbe;
    m_data.resize(m_d);
    generate(begin(m_data), end(m_data), ref(rbe));
}

void BCast::runOnline()
{
    vector<byte> data(numParties*m_d); // save data from other parties

    timer->startSubTask("TestComm", 1);

    roundFunctionSameMsg(m_data.data(), data.data(), m_d);

    timer->endSubTask("TestComm", 1);
}