/*
    This file is part of FISCO-BCOS.

    FISCO-BCOS is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    FISCO-BCOS is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with FISCO-BCOS.  If not, see <http://www.gnu.org/licenses/>.
*/
/** @file SDFCryptoProvider.h
 * @author maggiewu
 * @date 2021-02-01
 */
#pragma once
#include "libsdf/swsds.h"
#include <stdio.h>
#include <cstdlib>
#include <list>
#include <string>
#include <cstring>
using namespace std;
namespace dev
{
class KeyPair;
namespace crypto
{
enum AlgorithmType : uint32_t
{
    SM2 = 0x00020100,      // SGD_SM2_1
    SM3 = 0x00000001,      // SGD_SM3
    SM4_CBC = 0x00002002,  // SGD_SM4_CBC
};
int PrintData(char*,unsigned char*,unsigned int, unsigned int);
class Key
{
public:
    unsigned char * PublicKey() const { return m_publicKey; }
    unsigned char * PrivateKey() const { return m_privateKey; }
    Key(void){};
    Key(unsigned char* privateKey, unsigned char* publicKey)
    {
        m_privateKey = privateKey;
        m_publicKey = publicKey;
    };
    Key(const unsigned int keyIndex, char *& password)
    {
        m_keyIndex = keyIndex;
        m_keyPassword = password;
    };
    unsigned int Identifier() { return m_keyIndex; };
    char * Password() { return m_keyPassword; };
    void setPrivateKey(unsigned char* privateKey, unsigned int len)
    {
        m_privateKey = (unsigned char*)malloc(len * sizeof(char));
        memcpy(m_privateKey, privateKey, len);
    };
    void setPublicKey(unsigned char* publicKey, unsigned int len)
    {
        m_publicKey = (unsigned char*)malloc(len * sizeof(char));
        memcpy(m_publicKey, publicKey, len);
    };
    ~Key(){
        free(m_privateKey);
        free(m_publicKey);
    }

private:
    unsigned int m_keyIndex;
    char * m_keyPassword;
    unsigned char * m_privateKey;
    unsigned char * m_publicKey;
};

class SessionPool
{
public:
    SessionPool(int size, void * deviceHandle);
    virtual ~SessionPool();
    void * GetSession();
    void ReturnSession(void * session);


private:
    void * m_deviceHandle;
    size_t m_size;
    std::list<void *> m_pool;
};

/**
 *  SDFCryptoProvider suply SDF function calls
 *  Singleton
 */
class SDFCryptoProvider
{
private:
    void * m_deviceHandle;
    SessionPool* m_sessionPool;
    SDFCryptoProvider();
    ~SDFCryptoProvider();
    SDFCryptoProvider(const SDFCryptoProvider&);
    SDFCryptoProvider& operator=(const SDFCryptoProvider&);
    // std::mutex mut;

public:
    /**
     * Return the instance
     */
    static SDFCryptoProvider& GetInstance();

    /**
     * Generate key
     * Return error code
     */
    unsigned int KeyGen(AlgorithmType algorithm, Key* key);

    /**
     * Sign
     */
    unsigned int Sign(Key const& key, AlgorithmType algorithm, char const* digest,
        unsigned int const digestLen, unsigned char* signature, unsigned int* signatureLen);

    /**
     * Verify signature
     */
    unsigned int Verify(Key const& key, AlgorithmType algorithm, char const* digest,
        unsigned int const digestLen, char const* signature,
        unsigned int const signatureLen, bool* result);

    /**
     * Make hash
     */
    unsigned int Hash(Key* key, AlgorithmType algorithm, char const* message,
        unsigned int const messageLen, unsigned char*  digest, unsigned int* digestLen);

    /**
     * Encrypt
     */
    unsigned int Encrypt(Key const& key, AlgorithmType algorithm, char const* plantext,
        unsigned int const plantextLen, unsigned char* cyphertext, unsigned int* cyphertextLen);

    /**
     * Decrypt
     */
    unsigned int Decrypt(Key const& key, AlgorithmType algorithm, char const* cyphertext,
        unsigned int const cyphertextLen, unsigned char* plantext, unsigned int* plantextLen);

    /**
     * Make sm3 hash with z value
     */
    unsigned int HashWithZ(Key* key, AlgorithmType algorithm, char const* zValue,
        unsigned int const zValueLen, char const* message, unsigned int const messageLen,
        unsigned char* digest, unsigned int* digestLen);

    static char * GetErrorMessage(unsigned int code);
};

class TypeHelper{
public:
    unsigned int i;
    bool b;
    unsigned char * data;
    int charLen;
    unsigned int * NewUintPointer(){
        return &i;
    }

    unsigned int GetUintValue(){
        return i;
    }

    bool * NewBoolPointer(){
        return &b;
    }

    bool GetBoolValue(){
        return b;
    }
    unsigned char * NewUcharPoint(int len){
        charLen = len;
        unsigned char d[len];
        data = d;
        return data; 
    }
    char * GetUcharHexValue(){
        return toHex(data,charLen);
    }

    char * GetUcharHexValue(unsigned char* ucharString, int len){
        return toHex(ucharString,len);
    }

private:
    char* toHex(unsigned char *  data, int len)
    {
        
        static char const* hexdigits = "0123456789abcdef";
        std::string hex(len * 2, '0');
        int position = 0;
        for (int i = 0; i < len; i++)
        {
            hex[position++] = hexdigits[(data[i] >> 4) & 0x0f];
            hex[position++] = hexdigits[data[i] & 0x0f];
        }
        char * c_hex = new char[len * 2 +1];
        strcpy(c_hex,hex.c_str());
        return c_hex;
    }
};

}  // namespace crypto
}  // namespace dev
