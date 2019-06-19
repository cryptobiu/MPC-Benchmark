//
// Created by liork on 3/19/19.
//

#include "ExampleUdp.h"

ExampleUdp::ExampleUdp(int partyId, int numOfParties, string partiesFile, int dataSize):
_udp(partyId, numOfParties, partiesFile, 1, "UDPComm"), _rxData(numOfParties)

{
    _partyId = partyId;
    _numOfParties = numOfParties;
    _dataSize = dataSize;

    for (int idx = 0; idx < _dataSize; ++idx)
        _txData.emplace_back(idx);
}

void ExampleUdp::round()
{
    _udp.join(true);
    int ret;
    vector<bool> rxflags(_numOfParties);
    for (int idx = 0; idx < _numOfParties; ++idx)
    {
        if (_partyId == idx)
            continue;

        _rxData[idx].resize(_dataSize);
    }

    // Transmit data

    for (int idx = 0; idx < _numOfParties; ++idx)
    {
        if(_partyId == idx)
            continue;
        ret = _udp.write(_txData.data(), _dataSize, idx, 0);
    }

    int cnt = 0;
    while (cnt < _numOfParties - 1)
    {
        for (int idx = 0; idx < _numOfParties; ++idx)
        {
            if(_partyId == idx)
                continue;

            // Already received data
            if(rxflags[idx])
                continue;

            ret = _udp.read(_rxData[idx].data(), _rxData[idx].size() * sizeof(byte), idx, 0);

            if(ret < 0)
                continue;
            else if (ret == _rxData[idx].size() * sizeof(byte))
            {
                rxflags[idx] = true;
                ++cnt;
            }
        }

        this_thread::sleep_for(chrono::milliseconds(200));

    }
}
