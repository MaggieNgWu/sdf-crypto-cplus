#include "SDFCryptoProvider.h"
#include<string>
#include<iostream>

using namespace std;
using namespace dev;
using namespace crypto;

int main(int, const char* argv[]){
    SDFCryptoProvider& provider = SDFCryptoProvider::GetInstance();
    char * input = (char *)malloc(8*sizeof(char));
    strncpy(input,"test-sdf",8);
    char * out = new char[32];
    unsigned int outLen;
    unsigned int code = provider.Hash(nullptr,dev::crypto::SM3 , (const char*)input, 8, out,&outLen);
    cout << provider.GetErrorMessage(code) << endl;
    cout << out <<endl;

    Key key=Key();
    code = provider.KeyGen(SM2,&key);
    cout << "****KeyGen****" << endl;
    cout << provider.GetErrorMessage(code) << endl;
    cout <<key.PublicKey()<<endl;

    cout << "****Sign****" << endl;
    char * signature = (char *)malloc(64*sizeof(char));
    unsigned int len;
    provider.Sign(key,SM2,out,32,signature,&len);
    cout <<signature<<endl;

    cout << "****Verify****" << endl;
    bool result;
    provider.Verify(key,SM2,out,32,signature,64,&result);
    cout <<result<<endl;

    return 0;
}
