/*
 * xApp authorization framework to be integrated into the reference RAN Intelligent Controller (RIC) of the 
 * Linux Foundation (LF) for distributing access tokens to xApps from an OAUTH 2.0 server using JSON web tokens
 * as the execution method of the tokens
 *
 * Library for generating a JSON Web Token
 *
 * ! file xrf_jwt.cpp
 *  \brief
 * \author: Tolga Omer Atalay
 * \Affiliation: VirginiaTech
 * \date: 2022
 * \email: tolgaoa@vt.edu
*/

#include "xrf_jwt.hpp"

#include <string>
#include <iostream>

#include <boost/uuid/uuid.hpp>            // uuid class
#include <boost/uuid/uuid_generators.hpp> // generators
#include <boost/uuid/uuid_io.hpp>         // streaming operators etc.


#include <jwt/jwt.hpp>


using namespace xrf::app;

bool xrf_jwt::generate_signature(const std::string& xapp_consumer_id,
                                 const std::string& target_xapp_id,
                                 std::string& signature, 
				 std::unordered_map<std::string, EVP_PKEY*>& jwks) {

	EVP_PKEY *priv_key;
	std::string kid;

	generate_key_pair(jwks, kid, priv_key);

	EVP_PKEY *prvKey;
	prvKey = EVP_PKEY_new();
	FILE* fp = fopen("prv_xrf", "r");
	PEM_read_PrivateKey(fp,&prvKey,NULL,NULL);

        std::string keypriv =
R"(-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDBeLCgapjZmvTatMHaYX3A02+0Ys3Tr8kda+E9DFnmCSiCOEig519fT
13edeU8YdDugBwYFK4EEACKhZANiAASibEL3JxzwCRdLBZCm7WQ3kWaDL+wP8omo
3e2VJmZQRnfDdzopgl8r3s8w5JlBpR17J0Gir8g6CVBA6PzMuq5urkilppSINDnR
4mDv0+9e4uJVQf3xwEv+jywNUH+wbPM=
-----END EC PRIVATE KEY-----)";

	std::string keypriv1 = 
R"(-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----)";


	
	boost::uuids::uuid jti = boost::uuids::random_generator()();
        jwt::jwt_object obj{jwt::params::algorithm("RS256"),
        //jwt::jwt_object obj{jwt::params::algorithm("ES256"),
			jwt::params::headers({{"kid", "12-34-56"}}),
                        jwt::params::payload({{"iss", "nssl.xrf"},
                                            {"sub", target_xapp_id},
                                            {"aud", xapp_consumer_id},
                                            {"scope", "scope"},
                                            {"exp", "1000"}}),  // seconds
                        jwt::params::secret(keypriv1)};
                        //jwt::params::secret(keypriv)};
        signature = obj.signature();
        return true;
}


bool xrf_jwt::generate_key_pair(std::unordered_map<std::string, EVP_PKEY*>& jwks,
			        std::string& kid, EVP_PKEY *priv_key) {

	srand (time(NULL));
	kid = rand() % 10000000 + 99999999;

	std::pair<EVP_PKEY*,EVP_PKEY*> key_pair = GetKeyRSApair();
	priv_key = key_pair.first;

	jwks[kid] = key_pair.second; 

        return true;

}



//https://www.codeproject.com/Tips/5325577/RSA-Key-Pair-via-OpenSSL
std::pair<EVP_PKEY*,EVP_PKEY*> xrf_jwt::GetKeyRSApair()
{
	auto bne = BN_new();         //refer to https://www.openssl.org/docs/man1.0.2/man3/bn.html
	auto ret = BN_set_word(bne, RSA_F4);

	int bits = 2048;
	RSA *r = RSA_new();
	RSA_generate_key_ex(r, bits, bne, NULL);  //here we generate the RSA keys

	//we use a memory BIO to store the keys
	BIO *bp_public  = BIO_new(BIO_s_mem());PEM_write_bio_RSAPublicKey (bp_public, r);
	BIO *bp_private = BIO_new(BIO_s_mem());
	PEM_write_bio_RSAPrivateKey(bp_private, r, NULL, NULL, 0, NULL, NULL);

	auto pri_len = BIO_pending(bp_private);   //once the data is written to a 
					      //memory/file BIO, we get the size
	auto pub_len = BIO_pending(bp_public);
	char *pri_key = (char*) malloc(pri_len + 1);
	char *pub_key = (char*) malloc(pub_len + 1);

	BIO_read(bp_private, pri_key, pri_len);   //now we read the BIO into a buffer
	BIO_read(bp_public, pub_key, pub_len);

	pri_key[pri_len] = '\0';
	pub_key[pub_len] = '\0';

	//printf("\n%s\n:\n%s\n", pri_key, pub_key);fflush(stdout);  //now we print the keys 
	//to stdout (DO NOT PRINT private key in production code, this has to be a secret)

	BIO *pbkeybio = NULL;
	pbkeybio=BIO_new_mem_buf((void*) pub_key, pub_len);  //we create a buffer BIO 
				     //(this is different from the memory BIO created earlier)
	BIO *prkeybio = NULL;
	prkeybio=BIO_new_mem_buf((void*) pri_key, pri_len);

	RSA *pb_rsa = NULL;
	RSA *p_rsa = NULL;

	pb_rsa = PEM_read_bio_RSAPublicKey(pbkeybio, &pb_rsa, NULL, NULL);  //now we read the 
								   //BIO to get the RSA key
	p_rsa = PEM_read_bio_RSAPrivateKey(prkeybio, &p_rsa, NULL, NULL);

	EVP_PKEY *evp_pbkey = EVP_PKEY_new();  //we want EVP keys , openssl libraries 
			 //work best with this type, https://wiki.openssl.org/index.php/EVP
	EVP_PKEY_assign_RSA(evp_pbkey, pb_rsa);

	EVP_PKEY *evp_prkey = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(evp_prkey, p_rsa);

	//clean up
	free(pri_key);free(pub_key);
	BIO_free_all(bp_public);BIO_free_all(bp_private);
	BIO_free(pbkeybio);BIO_free(prkeybio);
	BN_free(bne);
	RSA_free(r);

	return {evp_pbkey,evp_prkey};
}


void xrf_jwt::test_jwt(){

using namespace jwt::params;


std::string keypub =
    R"(-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAv628x9EfQ/1drsLo9Pyb
zv977S1s4NP4S01POgTeFUxjuQuLJsQp1f+WYXF4U4abgz2w2Jkw9h1oUK484iIz
ud5/aitc9lYlqGYZ2G+CPow7/MuTxc645OANO41LuZQ3iIZhIt8KuRME8zE+/cWj
DckFvCIirxz61w3+IHe66ln8tZWApelKAYixJD7aoLxPcA63olrx8ETU0RKRWA3N
TjE6cIrkfani0jQ4OwZSMOvApqFWy1aqNSnzoPCmV4jB4/vUJUkQ52z72RAo/Bdh
Blgo4cvP0UzpGNF4wGJw8b8gu+q4ZNgaOORI5kTeV/rucjSVuW/l9vfHQbwDircf
YY7E27VuTJ7Uq/bCeqKBJTY+Qsc3JLgbuRXv+3vYIVLtVzfHdqiTgE4sow2ytEH0
yJJOmsG5wmt5sC/X9/RAe6D3u9BXzAEDq2Lg7dEZVxDnP/GFxbxzGWutNS3dkH0D
5k5LAKCUfd3+p2AJvxwZw4m6r5xUTZKV7T3jHQfRsr3HtAGOvgmMbqmR9M33Aok3
L5snW3Hwc/ma+4NewRQfq1DlMSlZ7ODFeTB+33MJ1yp+CHZb7QM96XmM9NrXVGQS
/WH0nywNTp7lv7TcCjupaesTq+jp579af6oNZWvYsHAM91r0bNPltvmAvg987u3y
9XiCLTOu0UXPWy9nmuhqF4MCAwEAAQ==
-----END PUBLIC KEY-----)";


        std::string key =
R"(-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----)";



	std::cout << "Create string view of the private key" << std::endl;
	jwt::string_view sv = key;
	std::cout << key << std::endl;

	std::cout << "Create string view of the public key" << std::endl;
	jwt::string_view sv1 = keypub;
	std::cout << keypub << std::endl;

	std::cout << "Create JWT Object" << std::endl;
	// Create JWT object
        jwt::jwt_object obj{algorithm("RS256"), payload({{"some", "payload"}}),
                      secret(key)};

	std::cout << obj.header() << std::endl;
	std::cout << obj.payload() << std::endl;
	std::cout << "JWT Object Printed" << std::endl;
	

	std::cout << "encode and sign the object" << std::endl;
        // Get the encoded string/assertion
        auto enc_str = obj.signature();
        std::cout << enc_str << std::endl;
	std::cout << "encrypted token printed" << std::endl;

        // Decode
        auto dec_obj = jwt::decode(enc_str, algorithms({"RS256"}), secret(keypub));
        std::cout << dec_obj.header() << std::endl;
        std::cout << dec_obj.payload() << std::endl;
	std::cout << "token printed" << std::endl;
}

