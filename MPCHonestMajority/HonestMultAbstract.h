//
// Created by meital on 18/04/17.
//

#ifndef MPCHONESTMAJORITY_HONESTMULTABSTRACT_H
#define MPCHONESTMAJORITY_HONESTMULTABSTRACT_H

#include <vector>
#include <libscapi/include/primitives/Mersenne.hpp>

template <class FieldType>
class ProtocolParty;

template <typename FieldType>
class HonestMultAbstract {

public:

    virtual void invokeOffline() = 0;

    virtual void mult(FieldType *a, FieldType *b, vector <FieldType> &cToFill, int numOfTrupples) = 0;
};

#endif //MPCHONESTMAJORITY_HONESTMULTABSTRACT_H