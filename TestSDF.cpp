#include "SDFCryptoProvider.h"
#include<string>
#include<iostream>

using namespace std;
using namespace dev;
using namespace crypto;

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


int main(int, const char* argv[]){
    SDFCryptoProvider& provider = SDFCryptoProvider::GetInstance();
    char * input = (char *)malloc(8*sizeof(char));
    strncpy(input,"test-sdf",8);

    // Make hash
    cout << "**************Make SM3 Hash************************"<<endl;
    unsigned char bHashData[64] = {0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,
                                0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,
                                0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,
                                0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64};

    unsigned char bHashStdResult[32] = {0xde,0xbe,0x9f,0xf9,0x22,0x75,0xb8,0xa1,0x38,0x60,0x48,0x89,0xc1,0x8e,0x5a,0x4d,
                                    0x6f,0xdb,0x70,0xe5,0x38,0x7e,0x57,0x65,0x29,0x3d,0xcb,0xa3,0x9c,0x0c,0x57,0x32};
    unsigned char bHashResult[256];
    unsigned int uiHashResultLen;
    unsigned int code = provider.Hash(nullptr,SM3,(char *)bHashData,64, (char *) bHashResult, &uiHashResultLen);
    cout << "****Make Hash****" << endl;
    cout<<"Call Hash:" << provider.GetErrorMessage(code) << endl;
    PrintData((char *)"Hash",(char *)bHashResult,32,16);
    if((uiHashResultLen != 32) || (memcmp(bHashStdResult, bHashResult, 32) != 0))
    {
        cout << "杂凑值与标准数据杂凑值比较失败." << endl;
    }
    else
    {
        cout << "标准数据杂凑运算验证成功。" << endl;
    }

    Key key=Key();
    code = provider.KeyGen(SM2,&key);
    cout << "****KeyGen****" << endl;
    cout << provider.GetErrorMessage(code) << endl;
    PrintData((char *)"public key",key.PublicKey(),64,16);

    cout << "****Sign****" << endl;
    char * signature = (char *)malloc(64*sizeof(char));
    unsigned int len;
    provider.Sign(key,SM2,out,32,signature,&len);
    cout << provider.GetErrorMessage(code) << endl;
    PrintData((char *)"signature",signature,64,16);

    cout << "****Verify****" << endl;
    bool result;
    code = provider.Verify(key,SM2,out,32,signature,64,&result);
    cout << provider.GetErrorMessage(code) << endl;
    cout <<"verify result"<< result<<endl;

    return 0;
}

