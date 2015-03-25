#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<openssl/rsa.h>
#include<openssl/pem.h>
#include<openssl/err.h>
#include<assert.h>
#include<string>
#include <sstream>

#define OPENSSLKEY "test.key"
#define PUBLICKEY "test_pub.key"
#define ENCRYPT_FILE "mywords.en"
#define BUFFSIZE 1024

using namespace std;

static void hexdump(FILE *f, const char *title, const unsigned char *s, int len)
{  
//#define HEXDUMPTYPE 

#ifdef HEXDUMPTYPE
	
	int n = 0;
	fprintf(f, "%s", title);
	
	for (n = 0; n < len; ++n) 
	{		
        fprintf(f, "%02x", s[n]);  
    }  	
#else
    int n = 0;  	
    fprintf(f, "%s", title);  
	
    for (; n < len; ++n) 
	{  
        if ((n % 16) == 0) 
		{  
                fprintf(f, "\n%04x", n);  
        }  
		
        fprintf(f, " %02x", s[n]);  
    }  
  
    fprintf(f, "\n");  
#endif
} 

#if 0
static void hexload(const string &hex_text, string &text)
{
	int i =0;
	while(true)  
    {  
        char c;  
        int x;  
        stringstream ss;  
        ss<<hex<<hex_text.substr(i, 2).c_str();  
        ss>>x;  
        c = (char)x;  
        text += c;  
        if(i >= (int)hex_text.length() - 2)
		{	
			break;  
		}
		
        i += 2;  
    }  	
}
#endif

std::string EncodeRSAKeyFile( const std::string& strPemFileName, const std::string& strData )
{
	if (strPemFileName.empty() || strData.empty())
	{
		assert(false);
		return "";
	}
	
	FILE* hPubKeyFile = NULL;
	hPubKeyFile = fopen(strPemFileName.c_str(), "rb");
	if(hPubKeyFile == NULL)
	{
		assert(false);
		return ""; 
	}
	
	std::string strRet;
	RSA *pRSAPublicKey = RSA_new();
	if(PEM_read_RSA_PUBKEY(hPubKeyFile, &pRSAPublicKey, NULL, NULL) == NULL)
	{
		assert(false);
		return "";
	}

	int nLen = RSA_size(pRSAPublicKey);
	char* pEncode = new char[nLen + 1];
	int ret = RSA_public_encrypt(strData.length(), (const unsigned char*)strData.c_str(), (unsigned char*)pEncode, pRSAPublicKey, RSA_NO_PADDING/* RSA_NO_PADDING  RSA_PKCS1_PADDING */);
	if (ret >= 0)
	{
		strRet = std::string(pEncode, ret);
	}
	
	delete[] pEncode;
	RSA_free(pRSAPublicKey);
	fclose(hPubKeyFile);
	CRYPTO_cleanup_all_ex_data(); 
	return strRet;
}

std::string DecodeRSAKeyFile( const std::string& strPemFileName, const std::string& strData )
{
	if (strPemFileName.empty() || strData.empty())
	{
		assert(false);
		return "";
	}
	
	FILE* hPriKeyFile = NULL;
	hPriKeyFile = fopen(strPemFileName.c_str(),"rb");
	if(hPriKeyFile == NULL)
	{
		assert(false);
		return "";
	}
	
	std::string strRet;
	RSA* pRSAPriKey = RSA_new();
	if(PEM_read_RSAPrivateKey(hPriKeyFile, &pRSAPriKey, NULL, NULL) == NULL)
	{
		assert(false);
		return "";
	}
	
	int nLen = RSA_size(pRSAPriKey);
	char* pDecode = new char[nLen+1];

	int ret = RSA_private_decrypt(strData.length(), (const unsigned char*)strData.c_str(), (unsigned char*)pDecode, pRSAPriKey, RSA_NO_PADDING/* RSA_NO_PADDING  RSA_PKCS1_PADDING */);
	if(ret >= 0)
	{
		strRet = std::string((char*)pDecode, ret);
	}
	
	delete [] pDecode;
	RSA_free(pRSAPriKey);
	fclose(hPriKeyFile);
	CRYPTO_cleanup_all_ex_data(); 
	return strRet;
}

int main(void)
{
	/*
	FILE *file = NULL;
	if((file=fopen(ENCRYPT_FILE, "r"))==NULL)
	{
		perror("open encrypt file error");
		return NULL;    
	}

	char tmp[1024] = {0};
	int cnt = fread(tmp, 1, sizeof(tmp), file);
	if(0 != cnt)
	{
		//printf("after read %d from file:%s\n", cnt, tmp);
		hexdump(stdout, "== read from file ==: ", (unsigned char *)tmp, cnt);
		printf("\n");
		
		char *tmp_dec = my_decrypt(tmp, (char *)OPENSSLKEY);
		if(NULL != tmp_dec)
		{
			printf("after decrypt:%s\n", tmp_dec);
			free(tmp_dec);
			tmp_dec = NULL;
		}
	}	
		
	if(NULL != file)
	{
		fclose(file);
		file = NULL;
	}
	*/
	
	std::string str_pub_key_file(PUBLICKEY);
	std::string str_pri_key_file(OPENSSLKEY);
	//std::string str_source("When I fall in love with your, I have knew how to do if you do not love me.");
	//char *source=(char *)"When I fall in love with your, I have knew how to do if you do not love me.";
	//char *ptr_en,*ptr_de;
	//printf("source is: %s\n", str_source.c_str());
	
	std::string str_en = EncodeRSAKeyFile(std::string(PUBLICKEY), std::string("6df53a2c15e47f9a153cb70c83e73efaad05956bb304abf91b314dd457437bbea29d8197e69e317fa5323d8d80e924ec3c57a1c15f5f5f8acdaabaccf8454186"));
	//ptr_en=my_encrypt(source, (char *)PUBLICKEY);
	//printf("after encrypt:%s\n",ptr_en);
	hexdump(stdout, "== after encrypt ==: ", (const unsigned char*)str_en.c_str(), str_en.length());
	printf("\n");
	
	std::string str_de = DecodeRSAKeyFile(str_pri_key_file, str_en);
	//ptr_de=my_decrypt(ptr_en, (char *)OPENSSLKEY);
	printf("after decrypt: %s\n", str_de.c_str());
	
	return 0;
}
