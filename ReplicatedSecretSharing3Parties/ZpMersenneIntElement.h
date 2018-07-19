//
// Created by meital on 01/02/17.
//

#ifndef SECRET_SHARING_ZPMERSENNEINTELEMENT_H
#define SECRET_SHARING_ZPMERSENNEINTELEMENT_H

#include "NTL/ZZ_p.h"
#include "NTL/ZZ.h"


using namespace std;
using namespace NTL;



class ZpMersenneIntElement {

//private:
public: //TODO return to private after tesing

    static const unsigned int p = 2147483647;
    unsigned int elem;

    unsigned int numberOfTrailingZero(unsigned int number);
    unsigned int NumberOfTrailingZeroOpt(unsigned int i);


public:

    ZpMersenneIntElement(){elem = 0;};
    ZpMersenneIntElement(int elem);

    ZpMersenneIntElement& operator=(const ZpMersenneIntElement& other);
    inline bool operator!=(const ZpMersenneIntElement& other){ return !(other.elem == elem); };

    ZpMersenneIntElement operator+(const ZpMersenneIntElement& f2);
    ZpMersenneIntElement operator-(const ZpMersenneIntElement& f2);
    ZpMersenneIntElement operator/(const ZpMersenneIntElement& f2);
    ZpMersenneIntElement operator*(const ZpMersenneIntElement& f2);

    inline ZpMersenneIntElement& operator+=(const ZpMersenneIntElement& f2){ elem = (f2.elem + elem) %p; return *this;};
    ZpMersenneIntElement& operator*=(const ZpMersenneIntElement& f2);





};

inline ::ostream& operator<<(::ostream& s, const ZpMersenneIntElement& a){ return s << a.elem; };

#endif //SECRET_SHARING_ZPMERSENNEINTELEMENT_H
