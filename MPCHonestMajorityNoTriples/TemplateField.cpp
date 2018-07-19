//
// Created by meital on 15/11/16.
//

#include "TemplateField.h"
#include "ZpKaratsubaElement.h"


using namespace NTL;

template <>
TemplateField<ZZ_p>::TemplateField(long fieldParam) {

    this->fieldParam = fieldParam;
    this->elementSizeInBytes = NumBytes(fieldParam);//round up to the next byte
    this->elementSizeInBits = this->elementSizeInBytes*8;

    ZZ_p::init(ZZ(fieldParam));

    auto randomKey = prg.generateKey(128);
    prg.setKey(randomKey);

    m_ZERO = new ZZ_p(0);
    m_ONE = new ZZ_p(1);
}

template <>
TemplateField<ZpKaratsubaElement>::TemplateField(long fieldParam) {

    this->elementSizeInBytes = 5;//round up to the next byte
    this->elementSizeInBits = 40;

    auto randomKey = prg.generateKey(128);
    prg.setKey(randomKey);

    m_ZERO = new ZpKaratsubaElement(0);
    m_ONE = new ZpKaratsubaElement(1);
}


/*
 * The i-th field element. The ordering is arbitrary, *except* that
 * the 0-th field element must be the neutral w.r.t. addition, and the
 * 1-st field element must be the neutral w.r.t. multiplication.
 */
template <>
GF2E TemplateField<GF2E>::GetElement(long b) {

    if(b == 1)
    {
        return *GetOne();
    }
    if(b == 0)
    {
        return *GetZero();
    }
    GF2X element;

    for(int i=0; i < fieldParam; i++) {
        // set the coefficient of x^i to 1
        SetCoeff(element,i,(b >> i) & 1);
    }

    return to_GF2E(element);
}

template <>
ZpKaratsubaElement TemplateField<ZpKaratsubaElement>::GetElement(long b) {


    if(b == 1)
    {
        return *m_ONE;
    }
    if(b == 0)
    {
        return *m_ZERO;
    }
    else{
        ZpKaratsubaElement element(b);
        return element;
    }
}




template <>
ZZ_p TemplateField<ZZ_p>::GetElement(long b) {


    if(b == 1)
    {
        return *m_ONE;
    }
    if(b == 0)
    {
        return *m_ZERO;
    }
    else{
        ZZ_p element(b);
        return element;
    }
}



/**
 * the function create a field by:
 * generate the irreducible polynomial x^8 + x^4 + x^3 + x + 1 to work with
 * init the field with the newly generated polynomial
 */
template <>
TemplateField<GF2E>::TemplateField(long fieldParam) {

    this->fieldParam = fieldParam;
    this->elementSizeInBytes = fieldParam/8;
    this->elementSizeInBits = elementSizeInBytes*8;
    GF2X irreduciblePolynomial = BuildSparseIrred_GF2X(fieldParam);
    GF2E::init(irreduciblePolynomial);

    auto randomKey = prg.generateKey(128);
    prg.setKey(randomKey);

    m_ZERO = new GF2E(0);
    m_ONE = new GF2E(1);
}


template <>
void TemplateField<GF2E>::elementToBytes(unsigned char* elemenetInBytes, GF2E& element){

    BytesFromGF2X(elemenetInBytes,rep(element),fieldParam/8);
}


template <>
void TemplateField<ZpKaratsubaElement>::elementToBytes(unsigned char* elemenetInBytes, ZpKaratsubaElement& element){

    memcpy(elemenetInBytes, (byte*)(&element.elem), 5);
}

template <>
void TemplateField<ZpKaratsubaElement>::elementVectorToByteVector(vector<ZpKaratsubaElement> &elementVector, vector<byte> &byteVector){

    //TBD

}

template <>
ZpKaratsubaElement TemplateField<ZpKaratsubaElement>::bytesToElement(unsigned char* elemenetInBytes){

    long elemVal = 0;

    //copy the 5 bytes to a long element
    memcpy((byte*)&elemVal, elemenetInBytes, 5);

    return ZpKaratsubaElement(elemVal);
}


template <>
GF2E TemplateField<GF2E>::bytesToElement(unsigned char* elemenetInBytes){

    //first create a GF2X
    GF2X polynomialElement;

    //translate the bytes into a GF2X element
    GF2XFromBytes(polynomialElement, elemenetInBytes, fieldParam/8);

    //convert the GF2X to GF2E
    return to_GF2E(polynomialElement);
}


template <>
void TemplateField<ZZ_p>::elementToBytes(unsigned char* elemenetInBytes, ZZ_p& element){

    BytesFromZZ(elemenetInBytes,rep(element),elementSizeInBytes);
}



template <>
void TemplateField<ZZ_p>::elementVectorToByteVector(vector<ZZ_p> &elementVector, vector<byte> &byteVector){

    //TBD

}

template <>
void TemplateField<GF2E>::elementVectorToByteVector(vector<GF2E> &elementVector, vector<byte> &byteVector){

    //TBD

}


template <>
ZZ_p TemplateField<ZZ_p>::bytesToElement(unsigned char* elemenetInBytes){

    //first create a ZZ
    ZZ zz;

    //translate the bytes into a ZZ element
    ZZFromBytes(zz, elemenetInBytes, elementSizeInBytes);

    //convert the ZZ to ZZ_p
    return to_ZZ_p(zz);
}

