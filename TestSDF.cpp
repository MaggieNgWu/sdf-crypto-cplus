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
    PrintData("public key",key.PublicKey(),64,16);

    cout << "****Sign****" << endl;
    char * signature = (char *)malloc(64*sizeof(char));
    unsigned int len;
    provider.Sign(key,SM2,out,32,signature,&len);
    cout << provider.GetErrorMessage(code) << endl;
    PrintData("signature",signature,64,16);

    cout << "****Verify****" << endl;
    bool result;
    code = provider.Verify(key,SM2,out,32,signature,64,&result);
    cout << provider.GetErrorMessage(code) << endl;
    cout <<"verify result"<< result<<endl;

    return 0;
}

int PrintData(char *itemName, char *sourceData, unsigned int dataLength, unsigned int rowCount)
{
	int i, j;
	
	if((sourceData == NULL) || (rowCount == 0) || (dataLength == 0))
		return -1;
	
	if(itemName != NULL)
		printf("%s[%d]:\n", itemName, dataLength);
	
	for(i=0; i<(int)(dataLength/rowCount); i++)
	{
		printf("%08x  ",i * rowCount);

		for(j=0; j<(int)rowCount; j++)
		{
			printf("%02x ", *(sourceData + i*rowCount + j));
		}

		printf("\n");
	}

	if (!(dataLength % rowCount))
		return 0;
	
	printf("%08x  ", (dataLength/rowCount) * rowCount);

	for(j=0; j<(int)(dataLength%rowCount); j++)
	{
		printf("%02x ",*(sourceData + (dataLength/rowCount)*rowCount + j));
	}

	printf("\n");

	return 0;
}
