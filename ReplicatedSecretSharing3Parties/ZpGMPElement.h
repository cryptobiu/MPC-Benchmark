//
// Created by meital on 01/02/17.
//

#ifndef SECRET_SHARING_ZPGMPELEMENT_H
#define SECRET_SHARING_ZPGMPELEMENT_H


class ZpGMPElement {


    ZpGMPElement operator+(ZpGMPElement& f2);
    ZpGMPElement operator-(ZpGMPElement& f2);
    ZpGMPElement operator/(ZpGMPElement& f2);
    ZpGMPElement operator*(ZpGMPElement& f2);

};


#endif //SECRET_SHARING_ZPGMPELEMENT_H
