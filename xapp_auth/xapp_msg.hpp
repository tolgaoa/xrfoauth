#include <iostream>
#include <fstream>
#include <algorithm>
#include <openssl/x509v3.h> 
#include <openssl/bn.h> 
#include <openssl/asn1.h>
#include <openssl/x509.h> 
#include <openssl/x509_vfy.h> 
#include <openssl/pem.h> 
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <cstdio>
#include <openssl/rand.h>
#include <openssl/sha.h>

#define RND_LENGTH 128
#define SHA256_LENGTH 32
#define MSG_BUFLEN 640
#define PLAIN_LEN 320
#define RSA_SIG_LEN 512
#define	RSA_ENC_LEN 512
