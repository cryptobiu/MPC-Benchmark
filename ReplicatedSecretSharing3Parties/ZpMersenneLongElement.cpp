//
// Created by meital on 04/05/17.
//

#include "ZpMersenneLongElement.h"
#include <iostream>
#include <cmath>
#include <emmintrin.h>
#include <x86intrin.h>
#include "gmp.h"


using namespace std;


ZpMersenneLongElement& ZpMersenneLongElement::operator=(const ZpMersenneLongElement& other) // copy assignment
{
    if (this != &other) { // self-assignment check expected
        elem = other.elem;
    }
    return *this;
}


ZpMersenneLongElement::ZpMersenneLongElement(unsigned long elem) {

    this->elem = elem %p;



}
ZpMersenneLongElement ZpMersenneLongElement::operator-(const ZpMersenneLongElement& f2)
{
    ZpMersenneLongElement answer;

    long temp =  (long)elem - (long)f2.elem;

    if(temp<0){
        answer.elem = temp + p;
    }
    else{
        answer.elem = temp;
    }



    return answer;
}

ZpMersenneLongElement ZpMersenneLongElement::operator+(const ZpMersenneLongElement& f2)
{
    ZpMersenneLongElement answer;

    answer.elem = (elem + f2.elem);

    if(answer.elem>=p)
        answer.elem-=p;

    return answer;
}


ZpMersenneLongElement& ZpMersenneLongElement::operator+=(const ZpMersenneLongElement& f2){

    elem = (elem + f2.elem);

    if(elem>=p)
        elem-=p;

    return *this;

}

ZpMersenneLongElement ZpMersenneLongElement::operator*(const ZpMersenneLongElement& f2)
{

    ZpMersenneLongElement answer;

    unsigned long long high;
    unsigned long low = _mulx_u64(elem, f2.elem, &high);


    unsigned long low61 = (low & p);
    unsigned long low61to64 = (low>>61);
    unsigned long highShift3 = (high<<3);

    unsigned long res = low61 + low61to64 + highShift3;

    if(res >= p)
        res-= p;

    answer.elem = res;

    return answer;


}

ZpMersenneLongElement& ZpMersenneLongElement::operator*=(const ZpMersenneLongElement& f2){

    unsigned long long high;
    unsigned long low = _mulx_u64(elem, f2.elem, &high);


    unsigned long low61 = (low & p);
    unsigned long low61to64 = (low>>61);
    unsigned long highShift3 = (high<<3);

    unsigned long res = low61 + low61to64 + highShift3;

    if(res >= p)
        res-= p;

    elem = res;

    return *this;

}

ZpMersenneLongElement ZpMersenneLongElement::operator/(const ZpMersenneLongElement& f2)
{
    ZpMersenneLongElement answer;
    mpz_t d;
    mpz_t result;
    mpz_t mpz_elem;
    mpz_t mpz_me;
    mpz_init_set_str (d, "2305843009213693951", 10);
    mpz_init(mpz_elem);
    mpz_init(mpz_me);

    mpz_set_ui(mpz_elem, f2.elem);
    mpz_set_ui(mpz_me, elem);

    mpz_init(result);

    mpz_invert ( result, mpz_elem, d );

    mpz_mul (result, result, mpz_me);
    mpz_mod (result, result, d);


    answer.elem = mpz_get_ui(result);


    return answer;
}