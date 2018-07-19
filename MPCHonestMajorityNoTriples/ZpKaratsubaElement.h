//
// Created by hila on 05/05/17.
//

#ifndef ZPKARATSUBA_ZPKARATSUBAELEMENT_H
#define ZPKARATSUBA_ZPKARATSUBAELEMENT_H

#include "stdint.h"
#include <iostream>
#include "TemplateField.h"
#include <libscapi/include/primitives/Mersenne.hpp>



using namespace std;

class ZpKaratsubaElement {

public:
    unsigned long elem;

    ZpKaratsubaElement();
    ZpKaratsubaElement(long elem);

    ZpKaratsubaElement operator*(const ZpKaratsubaElement& f2);
    ZpKaratsubaElement operator+(const ZpKaratsubaElement& f2);
    ZpKaratsubaElement operator-(const ZpKaratsubaElement& f2);
    ZpKaratsubaElement operator/(const ZpKaratsubaElement& f2);

    ZpKaratsubaElement& operator=(const ZpKaratsubaElement& other);
    inline bool operator!=(const ZpKaratsubaElement& other){ return !(other.elem == elem); };

    ZpKaratsubaElement& operator+=(const ZpKaratsubaElement& f2);
    ZpKaratsubaElement& operator*=(const ZpKaratsubaElement& f2);

};

inline ::ostream& operator<<(::ostream& s, const ZpKaratsubaElement& a){ return s << a.elem; };
#endif //ZPKARATSUBA_ZPKARATSUBAELEMENT_H
