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
				 std::unordered_map<int, std::string>& jwks,
				 std::string& scope) {

	//EVP_PKEY *priv_key;
	//std::string kid;
	
	std::string priv_key;
	int kid; 
	generate_key_pair(jwks, priv_key, kid);

	spdlog::debug("Chosen private key pair: {}", priv_key);

	/*EVP_PKEY *prvKey;
	prvKey = EVP_PKEY_new();
	FILE* fp = fopen("prv_xrf", "r");
	PEM_read_PrivateKey(fp,&prvKey,NULL,NULL);*/

	
	boost::uuids::uuid jti = boost::uuids::random_generator()();
        jwt::jwt_object obj{jwt::params::algorithm("RS256"),
        //jwt::jwt_object obj{jwt::params::algorithm("ES256"),
			jwt::params::headers({{"kid", std::to_string(kid)}}),
                        jwt::params::payload({{"iss", "nssl.xrf"},
                                            {"sub", target_xapp_id},
                                            {"aud", xapp_consumer_id},
                                            {"scope", scope},
                                            {"exp", "1000"}}),  // seconds
                        //jwt::params::secret(tokenkey1priv)};
                        jwt::params::secret(priv_key)};
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

bool xrf_jwt::generate_key_pair(std::unordered_map<int, std::string>& jwks, std::string& priv_key, int& kid){
	
	spdlog::debug("Generating key pair for JWT");

        srand (time(NULL));
	kid = rand() % 10000000 + 99999999;
	

	spdlog::debug("Selecting key pair from set");
	std::pair<std::string, std::string> key_pair = selectRSApair();
	spdlog::debug("Selected key pair from set");

	priv_key = key_pair.first;
	jwks[kid] = key_pair.second;

	spdlog::debug("Saving public key: {}, for kid: {}", jwks[kid], kid);

	spdlog::debug("Finished generating key pair for JWT");

	return true;
};

std::pair<std::string, std::string> xrf_jwt::selectRSApair(){
        srand (time(NULL));
        int key = 0 + (rand() % 4);
	spdlog::debug("Will choose key: {}", key);
	
	spdlog::debug("Choosing private key pair");
	std::string privkey = privkeys[key];
	spdlog::debug("Choosing public key pair");
	std::string pubkey = pubkeys[key];

	spdlog::debug("Returning key pair");
	return {privkey, pubkey};
};


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


	std::cout << "Create string view of the private key" << std::endl;
	jwt::string_view sv = tokenkeypriv2;
	std::cout << tokenkeypriv1 << std::endl;

	std::cout << "Create string view of the public key" << std::endl;
	jwt::string_view sv1 = tokenkeypub2;
	std::cout << tokenkeypub1 << std::endl;

	std::cout << "Create JWT Object" << std::endl;
	// Create JWT object
        boost::uuids::uuid jti = boost::uuids::random_generator()();
        jwt::jwt_object obj{jwt::params::algorithm("RS256"),
        //jwt::jwt_object obj{jwt::params::algorithm("ES256"),
                        jwt::params::headers({{"kid", "12-34-56"}}),
                        jwt::params::payload({{"iss", "nssl.xrf"},
                                            {"sub", "targetxapp"},
                                            {"aud", "consumer"},
                                            {"scope", "read, write"},
                                            {"exp", "1000"}}),  // seconds
                        //jwt::params::secret(tokenkey1priv)};
                        jwt::params::secret(tokenkeypriv2)};

        /*jwt::jwt_object obj{algorithm("RS256"), payload({{"some", "payload"}}),
                      secret(tokenkeypriv1)};
	*/

	std::cout << obj.header() << std::endl;
	std::cout << obj.payload() << std::endl;
	std::cout << "JWT Object Printed" << std::endl;
	

	std::cout << "encode and sign the object" << std::endl;
        // Get the encoded string/assertion
        auto enc_str = obj.signature();
        std::cout << enc_str << std::endl;
	std::cout << "encrypted token printed" << std::endl;

        // Decode
        auto dec_obj = jwt::decode(enc_str, algorithms({"RS256"}), secret(tokenkeypub2));
        std::cout << dec_obj.header() << std::endl;
        std::cout << dec_obj.payload() << std::endl;
	std::cout << "token printed" << std::endl;
}

