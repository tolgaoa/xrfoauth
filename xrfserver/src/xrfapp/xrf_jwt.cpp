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


using namespace xrf::app;

bool xrf_jwt::generate_signature(const std::string& xapp_consumer_id,
                                 const std::string& target_xapp_id,
                                 std::string& signature, 
				 std::unordered_map<int, std::string>& jwks,
				 std::string& scope) {

	using namespace jwt::params;
	//EVP_PKEY *priv_key;
	//std::string kid;
	
	std::string priv_key;
	int kid; 
	generate_key_pair(jwks, priv_key, kid);

	//spdlog::debug("Chosen private key pair: {}", priv_key);
	
	//***************************Generate keys internally: not used right now*****************************
	/*EVP_PKEY *prvKey;
	prvKey = EVP_PKEY_new();
	FILE* fp = fopen("prv_xrf", "r");
	PEM_read_PrivateKey(fp,&prvKey,NULL,NULL);*/
	//****************************************************************************************************
	
	//******************************Token generation doesn't work with alignment**************************
	/*boost::uuids::uuid jti = boost::uuids::random_generator()();
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
	*/
	//****************************************************************************************************

        jwt::jwt_object obj{algorithm("RS256"),
                        headers({{"kid", std::to_string(kid)}}),
                        payload({{"iss", "nssl.xrf"}, {"sub", target_xapp_id}, {"aud", xapp_consumer_id}, {"scope", scope}, {"exp", "1000"}}),
                        secret(tokenkeypriv3)};


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

	std::string testkeypriv = 
	R"(-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----)";

	std::string testkeypub = 
	R"(-----BEGIN PUBLIC KEY-----MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAqe3ZPafs9rWERRdh7A4zAzsFFgFDwdZytmuA/9Cd67I34IOGy9pkS0DXwVo7THTCD2Y/8e88slhoMIIms7jzpuYJrrkLtx2oko/AXDudVQxGq6BFoipeV86Y22VsVlRunPogRqB7WQEwAgjOe5ax70ghMypWnLuMpS9+ChNfs4TIFPoFyw7Ki2V0/cJMAjfhlFqPJ55Itw1Lgz+bdr9Hn6eq3KXpcxXQ+FY530ekYZKBvr3dvUIUOIdHfwax3mCYmakmVGU5km5RbG8IBdEjga+WCgGgnYeenprWu2b+xC7F6ol7RAsNghhb+nxKJ0ZCEqKOeLf4iCdPb6awSIYlwcEu4F7q6icDa0/hOHHI5XF2JxIKgsqhIyYG7zF04blbRXQnQ1ZgQwcC/TdW22uD82zc9cbFHoscnWlfqQwTF7qrnvbtwO8LdZqGeC5O6j2sWxJD/qIGt0kym5MJZ7Vf215GYcjIiZGfSdg1/uwWrCAmedHmxa3z7c8A8oG5erVju676YwdOm0s4KvBaN/ZnoYVpN8gXv0IkDaccul4omMvtRRGeYxsCYK/E7mBgcnY3B9zZehOmenJ3kTEY+HIP6uyKAcq/xVYstKjy5hNfxvd0mrLuZgjI2SW3KSTCO7yi7ACqshWsbBSfYBbOXTfsVfo3IVNL8aXzZp6NNzpaAbsCAwEAAQ==-----END PUBLIC KEY-----)";


        std::string testkeypub1 =
        R"(-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAqe3ZPafs9rWERRdh7A4z
AzsFFgFDwdZytmuA/9Cd67I34IOGy9pkS0DXwVo7THTCD2Y/8e88slhoMIIms7jz
puYJrrkLtx2oko/AXDudVQxGq6BFoipeV86Y22VsVlRunPogRqB7WQEwAgjOe5ax
70ghMypWnLuMpS9+ChNfs4TIFPoFyw7Ki2V0/cJMAjfhlFqPJ55Itw1Lgz+bdr9H
n6eq3KXpcxXQ+FY530ekYZKBvr3dvUIUOIdHfwax3mCYmakmVGU5km5RbG8IBdEj
ga+WCgGgnYeenprWu2b+xC7F6ol7RAsNghhb+nxKJ0ZCEqKOeLf4iCdPb6awSIYl
wcEu4F7q6icDa0/hOHHI5XF2JxIKgsqhIyYG7zF04blbRXQnQ1ZgQwcC/TdW22uD
82zc9cbFHoscnWlfqQwTF7qrnvbtwO8LdZqGeC5O6j2sWxJD/qIGt0kym5MJZ7Vf
215GYcjIiZGfSdg1/uwWrCAmedHmxa3z7c8A8oG5erVju676YwdOm0s4KvBaN/Zn
oYVpN8gXv0IkDaccul4omMvtRRGeYxsCYK/E7mBgcnY3B9zZehOmenJ3kTEY+HIP
6uyKAcq/xVYstKjy5hNfxvd0mrLuZgjI2SW3KSTCO7yi7ACqshWsbBSfYBbOXTfs
Vfo3IVNL8aXzZp6NNzpaAbsCAwEAAQ==
-----END PUBLIC KEY-----)";



	spdlog::debug("==============Start JWT Test=============");

	auto key = "secret"; //Secret to use for the algorithm
	
	//Create JWT object
	//jwt::jwt_object obj{algorithm("HS256"), payload({{"some", "payload"}}), secret(key)};
       
       

	/*jwt::jwt_object obj{algorithm("RS256"),
                        headers({{"kid", "12-34-56"}}),
                        payload({{"iss", "nssl.xrf"}, {"test1", "test2"}}),
                        secret(testkeypriv)};
	*/



	//Decode
  jwt::jwt_object obj{algorithm("RS256"), secret(testkeypriv)};
  obj.add_claim("iss", "arun.muralidharan")
     .add_claim("exp", std::chrono::system_clock::now() - std::chrono::seconds{1})
     ;

  std::error_code ec;
  auto enc_str = obj.signature(ec);
  assert (!ec);

  //auto dec_obj = jwt::decode(enc_str, algorithms({"HS256"}), ec, secret(tokenkeypub3), verify(true));
  auto dec_obj = jwt::decode(enc_str, algorithms({"RS256"}), ec, verify(true));
  std::cout << ec << std::endl;
  assert (ec);
  assert (ec.value() == static_cast<int>(jwt::VerificationErrc::TokenExpired));

 
	
	//std::cout << dec_obj.header() << std::endl;
        //std::cout << dec_obj.payload() << std::endl;
	
	spdlog::debug("==============End JWT Test=============");

}

