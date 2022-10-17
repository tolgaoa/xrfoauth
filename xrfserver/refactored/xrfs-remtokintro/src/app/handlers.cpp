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

void handlers::validate_token(const std::string& request_body, std::string& validity){

        using namespace jwt::params;

        std::vector<std::string> mainpairs;
	boost::split(mainpairs, request_body, boost::is_any_of("&"), boost::token_compress_on);
	std::string token = mainpairs[0];
	std::string atkid = mainpairs[1];

        std::vector<std::string> kvpairs;
	boost::split(kvpairs, token, boost::is_any_of(","), boost::token_compress_on);
        std::vector<std::string> kv;
        std::string proc_token;

	std::string kid;

        for (auto i : kvpairs){
                i.erase(remove(i.begin(), i.end(), '"'), i.end());
                i.erase(remove(i.begin(), i.end(), '{'), i.end());
                i.erase(remove(i.begin(), i.end(), '}'), i.end());

                boost::split(kv, i, boost::is_any_of(":"), boost::token_compress_on);
                proc_token = kv[1];
                spdlog::debug("(Key, Value):  {}, {}", kv[0], kv[1]);
        }

        auto decoded = jwt::decode(proc_token, algorithms({"none"}), verify(false));

        spdlog::debug("======Decoding Token Header and Payload======");
        spdlog::debug("===Header===");
        spdlog::debug("{}", toString(decoded.header()));
        spdlog::debug("===Payload===");
        spdlog::debug("{}", toString(decoded.payload()));
/*
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
*/
        std::error_code ec;
	auto dec_obj = jwt::decode(token, algorithms({"RS256"}), ec, secret(atkid), verify(true));
        //If there is a verification error, uncomment to see the code
        //std::cout << ec << std::endl;
        assert (ec);
        validity = "true";
        spdlog::debug("Introspection Complete");

	


};
