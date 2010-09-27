/*
  p2pship - A peer-to-peer framework for various applications
  Copyright (C) 2007-2010  Helsinki Institute for Information Technology
  
  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License
  as published by the Free Software Foundation; either version 2
  of the License, or (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.
  
  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/
#include "ship_utils.h"
#include "ship_debug.h"
#include <stdio.h>
#include <stdarg.h>
#include <sys/stat.h>
#include "ident.h"
#include <time.h>
#include "processor_config.h"
#include <pwd.h>
#include <sys/stat.h>
#include <openssl/sha.h>

/* Encode something to base-64 
char *
ship_encode_base64(char *input, int length)
{
	unsigned char * ret = 0;
	unsigned int b64_len;
	int len = 0;
	
	b64_len = (((length + 2) / 3) * 4) + 3;
	ASSERT_TRUE(ret = (unsigned char *)malloc(b64_len), err);
	len = EVP_EncodeBlock(ret, input, length);
	ret[len] = 0;
 err:
	return ret;
}
*/
/* Decode base-64 
char *
ship_decode_base64(char *input, int length, int* outlen)
{
	unsigned char * ret = NULL;
	unsigned int bin_len;
	
	bin_len = (((length + 3) / 4) * 3);
	ASSERT_TRUE(ret = (unsigned char *)mallocz(bin_len), err);    
	*outlen = EVP_DecodeBlock(ret, input, length) - 1;
 err:
	return ret;
}
*/

/* Encode something to base-64 */
char *
ship_encode_base64(char *input, int length)
{
	char *ret = NULL;
	unsigned char in[48];
	int blen, i=0, ilen, len=0, olen=0;
	
	blen = (((length + 2) / 3) * 4) + 3;
	ASSERT_TRUE(ret = (char *)malloc(blen), err);
	
	while(i<length){
		
		ilen = (i+48<length)?48:length-i;
		memcpy (in, input, ilen);
		input += ilen;
		i += ilen;
		
		/* Each 48-byte text should encode to 64-byte binary */ 
		len = EVP_EncodeBlock((unsigned char*)ret+olen, in, ilen);
		olen += len;
	}

	ret[olen] = '\0';
	
err:
  	return ret;
}

/* Decode base-64 */
char *
ship_decode_base64(char *input, int length, int* outlen)
{
	char *ret = NULL;
	unsigned char in[64];
	int blen, len=0, i=0, ilen, olen=0;
	
	blen = (((length + 3) / 4) * 3);
	ASSERT_TRUE(ret = (char *)mallocz(blen), err); 
	
	while(i<length){
		
		ilen = (i+64<length)?64:length-i;
		memcpy (in, input, ilen);
		input += ilen;
		i += ilen;

		/* Each 64-byte text should decode to 48-byte binary */ 
		len = EVP_DecodeBlock((unsigned char*)ret+olen, in, ilen);
		olen += len;
	}
	
	*outlen = olen;
	
	/* remove padded = */
	while(*(--input) == '='){
		--(*outlen);
	}
	
err:
	return ret;
}

char *
ship_hash_sha1_base64(char *data, int datalen)
{
	char *digest = 0;
	char *ret = 0;
	
	ASSERT_TRUE(digest = (char *)mallocz(SHA_DIGEST_LENGTH), err);
	ASSERT_TRUE(SHA1((unsigned char*)data, datalen, (unsigned char*)digest), err);
	
	ASSERT_TRUE(ret = ship_encode_base64(digest, SHA_DIGEST_LENGTH), err);
	
 err:
	freez(digest);
	return ret;
}


/* hash function
 * return 0 for error 
 * otherwise, return size of hash value*/
int
ship_hash(const char *algo, unsigned char *data, unsigned char **hash)
{
	EVP_MD_CTX ctx;
	const EVP_MD *md; 
	int size = 0;
	int len = 0;
	
	*hash = 0;
	md = EVP_get_digestbyname(algo);
	if (!md) {
		LOG_ERROR("unknown digest algorithm %s\n", algo);
		goto err;
	}
	
	ASSERT_TRUE(size = EVP_MD_size(md) + 1, err);
	ASSERT_TRUE(*hash = mallocz(size * sizeof(unsigned char)), err);
	EVP_MD_CTX_init(&ctx);
	ASSERT_TRUE(EVP_DigestInit_ex(&ctx, md, NULL), err);
	ASSERT_TRUE(EVP_DigestUpdate(&ctx, data, strlen((char*)data)), err); 
	ASSERT_TRUE(EVP_DigestFinal_ex(&ctx, *hash, (unsigned int*)&len), err);
	EVP_MD_CTX_cleanup(&ctx);
	return len;
	
err:	
	freez(*hash);
	return 0;
}

unsigned char*
ship_hmac_sha1_base64(char *key, char* secret)
{
	int klen = 0;
	unsigned char *hmac_key = NULL;
	unsigned char *hmac_key64 = NULL;
	
	/* hmac key and shared secret */
	ASSERT_TRUE((hmac_key = mallocz(SHA_DIGEST_LENGTH * sizeof(unsigned char) + 1)), err);
	ASSERT_TRUE(HMAC(EVP_sha1(), secret, strlen(secret), (unsigned char*)key, strlen(key), hmac_key, (unsigned int*)&klen), err);
	hmac_key64 = (unsigned char*)ship_encode_base64((char*)hmac_key, klen);
 err:
	freez(hmac_key);
	return hmac_key64;
}

unsigned char*
ship_encrypt(const char *algo, unsigned char *key, unsigned char *iv, unsigned char *text, int *clen)
{
	unsigned char *cipher = NULL;
	unsigned char *c = NULL;
	unsigned char out[1024 + EVP_MAX_BLOCK_LENGTH];
	unsigned char in[1024];
	int olen = 0, ilen = 0, bsize = 0, i = 0, tlen = 0, csize = 0;
	EVP_CIPHER_CTX ctx;
	const EVP_CIPHER *ci;

	EVP_CIPHER_CTX_init (&ctx);
	ci = EVP_get_cipherbyname(algo);
	if (!ci) {
		LOG_ERROR("unknown cipher algorithm %s\n", algo);
		goto err;
	}
	
	ASSERT_TRUE(bsize = EVP_CIPHER_block_size(ci), err);
	tlen = strlen((char*)text);
	csize = ((tlen/bsize + 1) * bsize) + 1;
	ASSERT_TRUE(cipher = mallocz(csize * sizeof(unsigned char)), err);
	ASSERT_TRUE(EVP_EncryptInit_ex(&ctx, ci, NULL, key, iv), err);
	
	c = cipher;
	*clen = 0;
	while (i < tlen) {
		
		/* get part of text */
		ilen = (i+1024<tlen)?1024:tlen-i;
		memcpy (in, text, ilen);
		text += ilen;
		i += ilen;
		
		/* copy encrypt-part */
		ASSERT_TRUE(EVP_EncryptUpdate (&ctx, out, &olen, in, ilen), err);
		memcpy (c, out, olen);
		c += olen;
		
		/* increment cipher len */
		*clen += olen;
	}

	ASSERT_TRUE(EVP_EncryptFinal_ex(&ctx, out, &olen), err);
	memcpy (c, out, olen);
	*clen += olen;
	
	EVP_CIPHER_CTX_cleanup(&ctx);
	return cipher;
 err: 
	freez(cipher);
	return NULL;
}

unsigned char* 
ship_decrypt(const char *algo, unsigned char *key, 
	     unsigned char *iv, unsigned char *cipher, int clen)
{	
	unsigned char *decipher = NULL;
	unsigned char *d = NULL;
	unsigned char out[1024 + EVP_MAX_BLOCK_LENGTH];
	unsigned char in[1024];
	int olen = 0, ilen = 0, dlen = 0, bsize= 0, i = 0;

	EVP_CIPHER_CTX ctx;
	const EVP_CIPHER *ci;

	EVP_CIPHER_CTX_init (&ctx);
	ci = EVP_get_cipherbyname(algo);
	if(!ci) {
		LOG_ERROR("unknown cipher algorithm %s\n", algo);
		goto err;
	}
	
	ASSERT_TRUE(bsize = EVP_CIPHER_block_size(ci), err);
	dlen = clen + bsize + 1;
	ASSERT_TRUE(decipher = mallocz( dlen * sizeof(unsigned char)), err);

	/* d points to decipher */
	d = decipher;
	ASSERT_TRUE(EVP_DecryptInit_ex (&ctx, ci, NULL, key, iv), err);
	while (i < clen) {
		
		/* get part of cipher */
		ilen = (i+1024<clen)?1024:clen-i;
		memcpy (in, cipher, ilen);
		cipher += ilen;
		i += ilen;
		
		/* copy descrypt-part */
		ASSERT_TRUE(EVP_DecryptUpdate (&ctx, out, &olen, in, ilen), err);
		memcpy (d, out, olen);
		d += olen;
	}
	
	ASSERT_TRUE(EVP_DecryptFinal_ex(&ctx, out, &olen), err);
	memcpy (d, out, olen);
	
	EVP_CIPHER_CTX_cleanup(&ctx);
	return decipher;
err:
	freez(decipher);
	return NULL;
} 

/* encrypt string & encode to based64 format */
unsigned char*
ship_encrypt64 (const char *algo, unsigned char *key, unsigned char *iv, unsigned char *text)
{
	unsigned char *tmp = NULL;
	unsigned char *cipher64 = NULL;
	int clen = 0;
	
	ASSERT_TRUE(tmp = ship_encrypt(algo, key, iv, text, &clen), err);
	cipher64 = (unsigned char *)ship_encode_base64((char*)tmp, clen);
err:
	freez(tmp);
	return cipher64;
}

/* decode based64 data & decrypt to string */
unsigned char*
ship_decrypt64 (const char *algo, unsigned char *key, unsigned char *iv, unsigned char *cipher)
{
	unsigned char *tmp = NULL;
	unsigned char *decipher = NULL;
	int len = 0;
	
	ASSERT_TRUE(tmp = (unsigned char *)ship_decode_base64((char*)cipher, strlen((char*)cipher), &len), err);
	decipher = ship_decrypt(algo, key, iv, tmp, len);
 err:
	freez(tmp);
	return decipher;
}


/* public encrypt function
 * return 0 for error 
 * otherwise, return size of encrypted value*/
int 
ship_rsa_public_encrypt(RSA *pu_key, unsigned char *data, int inlen, unsigned char **cipher)
{
	int outlen = 0, ks = 0;
	
	ASSERT_TRUE(ks = RSA_size(pu_key), err);
	ASSERT_TRUE(*cipher = (unsigned char*)mallocz(ks * sizeof(unsigned char) +1), err);
	if ((outlen = RSA_public_encrypt(inlen, data, *cipher, pu_key, RSA_PKCS1_PADDING)) == -1) {
		LOG_ERROR("%s\n", ERR_error_string(ERR_get_error(), NULL));
		freez(*cipher);
	} 
err:	
	return outlen;
}

/* private decrypt function
 * return 0 for error 
 * otherwise, return size of decrypted value*/
int
ship_rsa_private_decrypt(RSA *pr_key, unsigned char *cipher, unsigned char **decipher)
{
	int outlen = 0, ks = 0;
	
	ASSERT_TRUE(ks = RSA_size(pr_key), err);
	ASSERT_TRUE(*decipher = (unsigned char *)mallocz(ks * sizeof(unsigned char) +1), err);
	if ((outlen = RSA_private_decrypt(ks, cipher, *decipher, pr_key , RSA_PKCS1_PADDING)) == -1) {
		LOG_ERROR("%s\n", ERR_error_string(ERR_get_error(), NULL));
		freez(*decipher);
	}
 err:
	return outlen;
}


/* createts a new key */
RSA *
ship_create_private_key()
{
	RSA *ret = 0, *rsa = 0;
	BIGNUM *bn = 0;
#ifdef HAVE_OPENSSL_0_9_8
	ASSERT_TRUE(rsa = RSA_new(), err);
	ASSERT_TRUE(bn = BN_new(), err);
	ASSERT_TRUE(BN_set_word(bn, RSA_F4), err);
	ASSERT_TRUE(RSA_generate_key_ex(rsa, 1024, bn, NULL) != -1, err);
	ret = rsa;
	rsa = NULL;
#else
	ASSERT_TRUE(ret = RSA_generate_key(1024, 17, NULL, NULL), err);
#endif
 err:
	if (bn) BN_free(bn);
	if (rsa) RSA_free(rsa);
	return ret;
}

/* creates a self-signed certificate for a key */
X509 *
ship_sign(char *subject, int ttl, RSA* signer_key)
{
	X509 *x = 0, *ret = 0;
	X509_NAME *tmp = 0;
	EVP_PKEY *pr_key = 0;
	
	ASSERT_TRUE(x = X509_new(), err);
	ASSERT_TRUE(pr_key = EVP_PKEY_new(), err);
	ASSERT_TRUE(EVP_PKEY_set1_RSA(pr_key, signer_key), err);
	
	ASSERT_TRUE(X509_set_version(x, 2), err); /* version 3 certificate */
	ASN1_INTEGER_set(X509_get_serialNumber(x), 0);
        ASSERT_TRUE(X509_gmtime_adj(X509_get_notBefore(x), 0), err);
	ASSERT_TRUE(X509_gmtime_adj(X509_get_notAfter(x), (long)ttl), err);
	
	ASSERT_TRUE(tmp = X509_get_subject_name(x), err);
	ASSERT_TRUE(X509_NAME_add_entry_by_txt(tmp, "CN", MBSTRING_ASC, 
					       (unsigned char*)subject, -1, -1, 0), err);
	ASSERT_TRUE(X509_set_subject_name(x, tmp), err);

	ASSERT_TRUE(X509_set_pubkey(x, pr_key), err);
	ASSERT_TRUE(X509_sign(x, pr_key, EVP_sha1()), err);
	ret = x;
	x = NULL;
 err:
	if (x)
		X509_free(x);
	if (pr_key)
		EVP_PKEY_free(pr_key);
	return ret;
}
