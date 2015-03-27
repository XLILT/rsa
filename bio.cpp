#include <string>
#include <iostream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>

using namespace std;

RSA *formatPublicRSAKey(string str_key)
{
	int n_len = str_key.size();      //str_key为base64编码的公钥字符串
	for(int i = 64; i < n_len; i+=64)
	{
		if(str_key[i] != '\n')
		{
			str_key.insert(i, "\n");
		}
		i++;
	}

	str_key.insert(0, "-----BEGIN PUBLIC KEY-----\n");
	str_key.append("\n-----END PUBLIC KEY-----\n");

	BIO *bio = NULL; 
	RSA *rsa = NULL; 
	char *chPublicKey = const_cast<char *>(str_key.c_str());
	if ((bio = BIO_new_mem_buf(chPublicKey, -1)) == NULL)       //从字符串读取RSA公钥
	{     
		cout<<"BIO_new_mem_buf failed!"<<endl;      
	}
	else
	{
		rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);   //从bio结构中得到rsa结构
		if (!rsa)
		{
			ERR_load_crypto_strings();
			char errBuf[512];
			ERR_error_string_n(ERR_get_error(), errBuf, sizeof(errBuf));
			cout<<"fomat public key failed["<<errBuf<<"]"<<endl;
			BIO_free_all(bio);
		}
	}

	return rsa;
}

RSA *formatPrivateRSAKey(string str_key)
{
	int n_len = str_key.size();      //str_key为base64编码的公钥字符串
	for(int i = 64; i < n_len; i+=64)
	{
		if(str_key[i] != '\n')
		{
			str_key.insert(i, "\n");
		}
		i++;
	}

	str_key.insert(0, "-----BEGIN RSA PRIVATE KEY-----\n");
	str_key.append("\n-----END RSA PRIVATE KEY-----\n");

	BIO *bio = NULL; 
	RSA *rsa = NULL; 
	char *chPublicKey = const_cast<char *>(str_key.c_str());
	if ((bio = BIO_new_mem_buf(chPublicKey, -1)) == NULL)       //从字符串读取RSA公钥
	{     
		cout<<"BIO_new_mem_buf failed!"<<endl;      
	}
	else
	{
		rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);   //从bio结构中得到rsa结构
		if (!rsa)
		{
			ERR_load_crypto_strings();
			char errBuf[512];
			ERR_error_string_n(ERR_get_error(), errBuf, sizeof(errBuf));
			cout<<"fomat public key failed["<<errBuf<<"]"<<endl;
			BIO_free_all(bio);
		}
	}

	return rsa;
}

