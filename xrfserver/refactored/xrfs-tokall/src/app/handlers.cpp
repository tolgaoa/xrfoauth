/*
 * xApp authorization framework to be integrated into the reference RAN Intelligent Controller (RIC) of the 
 * Linux Foundation (LF) for distributing access tokens to xApps from an OAUTH 2.0 server using JSON web tokens
 * as the execution method of the tokens
 * 
 * Specific subfunctions of the XRF for isolation
 *
 *
 * ! file func.cpp
 *  \brief
 * \author: Tolga Omer Atalay
 * \Affiliation: VirginiaTech
 * \date: 2022
 * \email: tolgaoa@vt.edu
*/


#include "handlers.hpp"


using namespace xrf::app;
xrf_jwt* xrf_jwt_inst = nullptr;

std::unordered_map<int, std::string> jwks; // kid .at() tokenpubkey where key is plaintext

template<class T> std::string toString(const T& x)
{
  std::ostringstream ss;
  ss << x;
  return ss.str();
}

void handlers::access_token_request(
                const std::string& request_main, std::string& token_rsp,
                int& http_code, const uint8_t http_version) {

        std::map<std::string, std::string> request;
        std::vector<std::string> kvpairs;
        boost::split(kvpairs, request_main, boost::is_any_of(","), boost::token_compress_on);

        for (auto i : kvpairs){
                i.erase(remove(i.begin(), i.end(), '"'), i.end());
                i.erase(remove(i.begin(), i.end(), '{'), i.end());
                i.erase(remove(i.begin(), i.end(), '}'), i.end());

                std::vector<std::string> kv;
                boost::split(kv, i, boost::is_any_of(":"), boost::token_compress_on);
                request[kv[0]] = kv[1];

                spdlog::debug("(Key, Value):  {}, {}", kv[0], kv[1]);
        }

        //JWT Object created here
        std::string sign = {};
        bool outcome = false;

        std::string scope = "read, write";

	int kid;
	std::string pubkeypair;

        outcome = xrf_jwt_inst->generate_signature(request.at("requester_ID"), request.at("target_ID"), sign, jwks, request.at("scope"), kid,  pubkeypair);


        spdlog::debug("JWT Access Token Signed: {}", sign);
        spdlog::debug("Key ID is: {}", kid);
        spdlog::debug("Pub_key pair is: {}", pubkeypair);	

	token_rsp = sign;
/*
        access_token_rsp.setAccessToken(sign);
        access_token_rsp.setTokenType("Bearer");
        http_code = 200;
*/
        //Uncomment to test JWT encode and decode
        //xrf_jwt_inst->test_jwt();
};

void handlers::fetch_token_key(const std::string& kid, std::string& token_pub_key) {

        spdlog::debug("Processing for key id: {}", kid);
        int kid_i = std::stoi(kid);
        token_pub_key = jwks.at(kid_i);
        spdlog::debug("Found pub key: {}", token_pub_key);

};

void handlers::validate_token(const std::string& token, std::string& validity){

        using namespace jwt::params;

        std::vector<std::string> kvpairs;
        boost::split(kvpairs, token, boost::is_any_of(","), boost::token_compress_on);
        std::vector<std::string> kv;
        std::string proc_token;

        for (auto i : kvpairs){
                i.erase(remove(i.begin(), i.end(), '"'), i.end());
                i.erase(remove(i.begin(), i.end(), '{'), i.end());
                i.erase(remove(i.begin(), i.end(), '}'), i.end());

                boost::split(kv, i, boost::is_any_of(":"), boost::token_compress_on);
                proc_token = kv[1];
                //spdlog::debug("(Key, Value):  {}, {}", kv[0], kv[1]);
        }

        std::string kid;
        auto decoded = jwt::decode(proc_token, algorithms({"none"}), verify(false));

        spdlog::debug("======Decoding Token Header and Payload======");
        spdlog::debug("===Header===");
        spdlog::debug("{}", toString(decoded.header()));
        spdlog::debug("===Payload===");
        spdlog::debug("{}", toString(decoded.payload()));

        std::string header_raw = toString(decoded.header());
        std::vector<std::string> header;
        boost::split(header, header_raw, boost::is_any_of(","), boost::token_compress_on);
        for (auto i : header){
                i.erase(remove(i.begin(), i.end(), '"'), i.end());
                i.erase(remove(i.begin(), i.end(), '{'), i.end());
                i.erase(remove(i.begin(), i.end(), '}'), i.end());

                std::vector<std::string> hkv;
                boost::split(hkv, i, boost::is_any_of(":"), boost::token_compress_on);
                for (auto k : hkv){
                        if (hkv[0] == "kid") {
                                kid = hkv[1];
                        }
                }
        }
        spdlog::debug("Key ID is: {}", kid);


        std::error_code ec;
        auto wbegin = std::chrono::high_resolution_clock::now();
        clock_t cstart = clock();
        auto dec_obj = jwt::decode(token, algorithms({"RS256"}), ec, secret(jwks.at(std::stoi(kid))), verify(true));
        auto wend = std::chrono::high_resolution_clock::now(); //Stop client wall clock
        clock_t cend = clock(); // Stop client cpu clock
        double celapsed = double(cend - cstart)/CLOCKS_PER_SEC; // calculate cpu time
        spdlog::debug("CPU-time for token validation: {} ms", celapsed * 1000.0);
        auto welapsed = std::chrono::duration<double, std::milli>(wend - wbegin); //calculate wall time
        spdlog::debug("Wall-time for token validation: {} ms", welapsed.count());
        auto celapseds = std::to_string(celapsed*1000.0);
        auto welapseds = std::to_string(welapsed.count());

        //If there is a verification error, uncomment to see the code
        //std::cout << ec << std::endl;
        //assert (ec);
        validity = "true";
        spdlog::debug("Introspection Complete");


};

