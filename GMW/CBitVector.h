//
// Created by moriya on 25/01/17.
//

#ifndef LIBSCAPI_CBITVECTOR_H
#define LIBSCAPI_CBITVECTOR_H

typedef unsigned char	BYTE;
#define SHA1_BYTES				20

const BYTE MASK_BIT[8] =
        {0x80, 0x40, 0x20, 0x10, 0x8, 0x4, 0x2, 0x1};

const BYTE CMASK_BIT[8] =
        {0x7f, 0xbf, 0xdf, 0xef, 0xf7, 0xfb, 0xfd, 0xfe};

const BYTE MASK_SET_BIT[2][8] =
        {{0,0,0,0,0,0,0,0},{0x80, 0x40, 0x20, 0x10, 0x8, 0x4, 0x2, 0x1}};

const BYTE MASK_SET_BIT_C[2][8] =
        {{0x80, 0x40, 0x20, 0x10, 0x8, 0x4, 0x2, 0x1},{0,0,0,0,0,0,0,0}};

const BYTE MASK_2BITS[8] =
        {0xc0, 0x60, 0x30, 0x18, 0xc, 0x6, 0x3, 0x1};

const BYTE CMASK_2BITS[8] =
        {0x3f, 0x9f, 0xcf, 0xe7, 0xf3, 0xf9, 0xfc, 0xfe};

const BYTE MASK_SET_2BITS[4][8] =
        {{0,0,0,0,0,0,0,0},
         {0x40, 0x20, 0x10, 0x8, 0x4, 0x2, 0x1, 0},
         {0x80, 0x40, 0x20, 0x10, 0x8, 0x4, 0x2, 0x1},
         {0xc0, 0x60, 0x30, 0x18, 0xc, 0x6, 0x3, 0x1}};

const BYTE G_TRUTH_TABLE[3][2][2] =
        {
                {0,0,0,0},
                {0,0,0,1},		// and
                {0,1,1,0},		// xor
        };

class CBitVector
{
public:
    CBitVector(){ m_pBits = NULL; m_nSize = 0; m_nRand = 0;}
    ~CBitVector(){ if(m_pBits) delete [] m_pBits; }

    void CreateinBytes(int bytes)
    {
        if( m_pBits ) delete [] m_pBits;
        m_pBits = new BYTE[bytes];
        m_nSize = bytes;
    }

    void Create(int bits)
    {
        //cout<<"in create with bits. bits = "<<bits<<endl;
        if( m_pBits ) delete [] m_pBits;

        m_nSize = (bits  + 7)/8;
        //m_nSize = size*SHA1_BYTES / 8;
        //cout<<"m_nSize = "<<m_nSize<<endl;
        m_pBits = new BYTE[m_nSize];
        //cout<<"after new"<<endl;
        //for (int i=0; i<m_nSize; i++){
        //    m_pBits[i] = 0;
        //}
    }

    void AddBit(BYTE b){
        //cout<<"in add bit"<<endl;
        if(!m_pBits) {
            //cout<<"array is null. creating array in size 8"<<endl;
            m_nSize = 1;
            m_pBits = new BYTE[m_nSize];
            for (int i=0; i<m_nSize; i++){
                m_pBits[i] = 0;
            }
        }
        if (counter == (m_nSize*8 - 1)){
           // cout<<"reached the array limit. enlarge..."<<endl;
            m_nSize *= 2;
            BYTE* temp = new BYTE[m_nSize];
            memcpy(temp, m_pBits, m_nSize/2);
            for (int i=m_nSize/2; i<m_nSize; i++){
                temp[i] = 0;
            }
            delete m_pBits;
            m_pBits = temp;
        }
       // cout<<"set bit "<<(int)b<<" in index "<<counter<<endl;
        SetBit(counter, b);
        counter++;
       /* cout<<"m_pBits:"<<endl;
        for (int i=0; i<m_nSize; i++){
            cout<<(int)m_pBits[i]<<" ";
        }
        cout<<endl;*/
    }

    BYTE GetBit(int idx)
    {
        return !!(m_pBits[idx>>3] & MASK_BIT[idx & 0x7]);
    }

    void SetBit(int idx, BYTE b)
    {
        m_pBits[idx>>3] = (m_pBits[idx>>3] & CMASK_BIT[idx & 0x7]) | MASK_SET_BIT_C[!b][idx & 0x7];
        /*cout<<"set bit "<<(int)b<<" in index "<<idx<<endl;
        cout<<"m_pBits:"<<endl;
        for (int i=0; i<m_nSize; i++){
            cout<<(int)m_pBits[i]<<" ";
        }
        cout<<endl;*/
    }

    void XORBit(int idx, BYTE b)
    {
        m_pBits[idx>>3] ^= MASK_SET_BIT_C[!b][idx & 0x7];
    }

    void XOR(BYTE* p, int len)
    {
        for(int i=0; i<len; i++)
            m_pBits[i] ^= p[i];
    }

    BYTE Get2Bits(int idx)
    {
        idx <<= 1;  // times 2
        return (m_pBits[idx>>3] & MASK_2BITS[idx & 0x7]) >> (6 - (idx & 0x7));
    }
    void Set2Bits(int idx, BYTE b)
    {
        idx <<= 1; // times 2
        m_pBits[idx>>3] = (m_pBits[idx>>3] & CMASK_2BITS[idx & 0x7]) | MASK_SET_2BITS[b & 0x3][idx & 0x7];
    }


    BYTE GetByte(int idx)
    {
        return m_pBits[idx];
    }
    BYTE* GetArr(){
        return m_pBits;
    }

    BYTE* GetArrToSend(){
        //cout<<"counter = "<<counter<<endl;
        //cout<<"m_nSize = "<<m_nSize<<endl;
        //cout<<"real bit size = "<<m_nSize*8<<endl;
        if ((m_nSize*8 - 1)  > counter){
            //cout<<"real size is bigger than actual size. copy..."<<endl;
            int size = (counter +7)/8;
            BYTE* temp = new BYTE[size];
            memcpy(temp, m_pBits, size);
            return temp;
        }
        return m_pBits;
    }

    void AttachBuf(BYTE* p, int size=-1){ m_pBits = p; m_nSize = size;}
    void DetachBuf(){ m_pBits = NULL; m_nSize = 0;}

    void Reset()
    {
        memset(m_pBits, 0, m_nSize);
        if (counter > 0) {
            m_nSize = 1;
            counter = 0;
            delete m_pBits;
            m_pBits = new BYTE[m_nSize];
            for (int i=0; i<m_nSize; i++){
                m_pBits[i] = 0;
            }
        }
    }

    int GetSize() { return m_nSize; }

private:
    BYTE*		m_pBits;
    int			m_nSize;
    int			m_nRand;
    int counter = 0;
};


#endif //LIBSCAPI_CBITVECTOR_H
