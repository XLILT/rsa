#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<openssl/rsa.h>
#include<openssl/pem.h>
#include<openssl/err.h>
#include<assert.h>
#include<string>
#include <sstream>

#define PRIVATEFILE "test.key"
#define PUBLICFILE "test_pub.key"
#define PUBLICKEY "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCdj4vPdDnZmlyeTCtv4TzzowZVNhxFIwm2GInvM1n5jumPtfGWjVCdEFrzaNUnK2EmNdZ8Z6Pn2vPuT44T6BM8Eltd9TlQCHGuJ2vdw/EpKaABCqtn8mfWk+NhAEWzatcjTW1A4rPNEYpVos/Z5wVKy1mnVyWXruTmcXwORCdkywIDAQAB"
#define PRIVATEKEY "MIICXAIBAAKBgQCdj4vPdDnZmlyeTCtv4TzzowZVNhxFIwm2GInvM1n5jumPtfGWjVCdEFrzaNUnK2EmNdZ8Z6Pn2vPuT44T6BM8Eltd9TlQCHGuJ2vdw/EpKaABCqtn8mfWk+NhAEWzatcjTW1A4rPNEYpVos/Z5wVKy1mnVyWXruTmcXwORCdkywIDAQABAoGAeP5dt+6h6hee3jTR+nV2EAZ1+4O1C+aPM5X+foDprDnx49ktb5aPfD2uClPLs+udC/G2Bwyzkn3SaoQPL/w8n+VBjverKxEqGYT1OEFlRZcGkjCKWjDOQFKnzsT3z20uF6aEmkpsO/bB8GTQc4WfnvU7vlQg4ff2j7aQFg5HJ9kCQQDPL8APcyAmTgglAC6cl8pgDSv7LXfe8dsQrUhG/1M58eYW3tk/y5qpLp5bDwHjX0ovq+o4cn3KCBcNZc3GsUMnAkEAwq6qRwq/U9jj719Ff8d+NjMuJNaUoD0xi1bZDy/W6lb/6jVNL2pIdWvmseoI0jHLAoyXOsB6kCPrUQXarq9HvQJBAIOdMcSeva2XpFTc6L9RLZ4Wv/mvyJY3zZGqgl+Xkqcco62jox6DmJwgoTf3MJvfzKC79O4mzQGqYfqA0VeHA8ECQG7Wgptvwv45vYvK8gaNzY2OFfdjM7sHG+34xBuhYPqKDamKLyePmzE+/VjNpbgGIU6SPId2jlECIjc+3gIWSQECQGIO7ydVYy5ggk4g0v4iAYz0OwNFj3c2S2RBoS9S0W2ZZSlqg78yDkH7T7V4slNODmCzkfSDANsEL9WTF2JYtko="
#define ENCRYPT_FILE "mywords.en"
#define BUFFSIZE 1024

using namespace std;

extern RSA *formatPublicRSAKey(string str_key);
extern RSA *formatPrivateRSAKey(string str_key);

static void hexdump(FILE *f, const char *title, const unsigned char *s, int len)
{  
#define HEXDUMPTYPE 

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
	
	int ret = RSA_public_encrypt(strData.length(), (const unsigned char*)strData.c_str(), (unsigned char*)pEncode, pRSAPublicKey, RSA_PKCS1_PADDING/* RSA_NO_PADDING  RSA_PKCS1_PADDING */);
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

	int ret = RSA_private_decrypt(strData.length(), (const unsigned char*)strData.c_str(), (unsigned char*)pDecode, pRSAPriKey, RSA_PKCS1_PADDING/* RSA_NO_PADDING  RSA_PKCS1_PADDING */);
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

std::string EncodeRSAKey( const std::string& strPemKey, const std::string& strData )
{
	if (strPemKey.empty() || strData.empty())
	{
		assert(false);
		return "";
	}
		
	std::string strRet;
	RSA *pRSAPublicKey = formatPublicRSAKey(strPemKey.c_str());
	if(pRSAPublicKey == NULL)
	{
		assert(false);
		return "";
	}

	int nLen = RSA_size(pRSAPublicKey);
	char* pEncode = new char[nLen + 1];
	
	int ret = RSA_public_encrypt(strData.length(), (const unsigned char*)strData.c_str(), (unsigned char*)pEncode, pRSAPublicKey, RSA_PKCS1_PADDING/* RSA_NO_PADDING  RSA_PKCS1_PADDING */);
	if (ret >= 0)
	{
		strRet = std::string(pEncode, ret);
	}
	
	delete[] pEncode;
	RSA_free(pRSAPublicKey);
	CRYPTO_cleanup_all_ex_data(); 
	return strRet;
}

std::string DecodeRSAKey( const std::string& strPemKey, const std::string& strData )
{
	if (strPemKey.empty() || strData.empty())
	{
		assert(false);
		return "";
	}
		
	std::string strRet;
	RSA* pRSAPriKey = formatPrivateRSAKey(strPemKey.c_str());
	if(pRSAPriKey == NULL)
	{
		assert(false);
		return "";
	}
	
	int nLen = RSA_size(pRSAPriKey);
	char* pDecode = new char[nLen+1];

	int ret = RSA_private_decrypt(strData.length(), (const unsigned char*)strData.c_str(), (unsigned char*)pDecode, pRSAPriKey, RSA_PKCS1_PADDING/* RSA_NO_PADDING  RSA_PKCS1_PADDING */);
	if(ret >= 0)
	{
		strRet = std::string((char*)pDecode, ret);
	}
	
	delete [] pDecode;
	RSA_free(pRSAPriKey);
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
	
	//std::string str_source("When I fall in love with your, I have knew how to do if you do not love me.");
	//char *source=(char *)"When I fall in love with your, I have knew how to do if you do not love me.";
	//char *ptr_en,*ptr_de;
	//printf("source is: %s\n", str_source.c_str());
	
	std::string str_en_file = EncodeRSAKeyFile(string(PUBLICFILE), std::string("I love dancing in the center of stage!"));
	//ptr_en=my_encrypt(source, (char *)PUBLICKEY);
	//printf("after encrypt:%s\n",ptr_en);
	hexdump(stdout, "== after encrypt with file ==: ", (const unsigned char*)str_en_file.c_str(), str_en_file.length());
	printf("\n");
	
	std::string str_de_file = DecodeRSAKeyFile(string(PRIVATEFILE), str_en_file);
	//ptr_de=my_decrypt(ptr_en, (char *)OPENSSLKEY);
	printf("after decrypt with file: %s\n", str_de_file.c_str());

	string tmp_enc_str_file;
	hexload(string("8922b6e3a9340c51c082ca289e087b0b20a27ccea041682b0427ec3413771b91c674eff4310bf3276c2c64333b9cedaaaa60cbe45f31a6a6f96eef26056ccf4439f7c703109c068df4be8f7d6ef211d7cc6cf822847af7c6243f63613db24a9488ce46e172c3b50f9be497c1a9119cace6f0367f6b3aa06b950c2b215612c0ad"), tmp_enc_str_file);
	std::string str_de_file2 = DecodeRSAKeyFile(string(PRIVATEFILE), tmp_enc_str_file);
	//ptr_de=my_decrypt(ptr_en, (char *)OPENSSLKEY);
	printf("after decrypt with file2: %s\n", str_de_file2.c_str());
	
	std::string str_en = EncodeRSAKey(std::string(PUBLICKEY), std::string("I love dancing in the center of stage!"));
	//ptr_en=my_encrypt(source, (char *)PUBLICKEY);
	//printf("after encrypt:%s\n",ptr_en);
	hexdump(stdout, "== after encrypt ==: ", (const unsigned char*)str_en.c_str(), str_en.length());
	printf("\n");
	
	std::string str_de = DecodeRSAKey(string(PRIVATEKEY), str_en);
	//ptr_de=my_decrypt(ptr_en, (char *)OPENSSLKEY);
	printf("after decrypt: %s\n", str_de.c_str());

	string tmp_enc_str;
	hexload(string("8922b6e3a9340c51c082ca289e087b0b20a27ccea041682b0427ec3413771b91c674eff4310bf3276c2c64333b9cedaaaa60cbe45f31a6a6f96eef26056ccf4439f7c703109c068df4be8f7d6ef211d7cc6cf822847af7c6243f63613db24a9488ce46e172c3b50f9be497c1a9119cace6f0367f6b3aa06b950c2b215612c0ad"), tmp_enc_str);
	std::string str_de2 = DecodeRSAKey(string(PRIVATEKEY), tmp_enc_str);
	//ptr_de=my_decrypt(ptr_en, (char *)OPENSSLKEY);
	printf("after decrypt2: %s\n", str_de2.c_str());
	
	return 0;
}
