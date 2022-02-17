/*
 * xApp authorization framework to be integrated into the reference RAN Intelligent Controller (RIC) of the 
 * Linux Foundation (LF) for distributing access tokens to xApps from an OAUTH 2.0 server using JSON web tokens
 * as the execution method of the tokens
 *
 *
 * ! file xrf_jwt.hpp
 *  \brief
 * \author: Tolga Omer Atalay
 * \Affiliation: VirginiaTech
 * \date: 2022
 * \email: tolgaoa@vt.edu
*/

#ifndef FILE_XRF_JWT_HPP_SEEN
#define FILE_XRF_JWT_HPP_SEEN

#include <string>


namespace xrf {
namespace app {

class xrf_jwt{
	private:
	public:
		void test_jwt();
		/*
		 * testing
		 */

		bool generate_signature(const std::string& xapp_consumer_id, const std::string& scope,
                                        const std::string& target_xapp_id,
                                        const std::string& xrf_id, std::string& signature) const;
                /*
                 * Generate signature for the requested consumer trying to access resources
                 * @param {xapp_consumer_id}: the id of the consumer xapp
                 * @param {scope}: name of the xapp services that the consumer is trying to access
                 * @param {target_xapp_id}: instance ID of the xapp service producer
                 * @param {xrf_id}: The id of the OAUTH 2.0 server that is being used which has been
                 * name xApp Repository Function (XRF)
                 * @param {signature}: generated signature
                 * return void
                 */

                bool get_secret_key(const std::string& scope, const std::string& target_xapp_id,
                                    std::string& key) const;
                /*
                 * Get the secret key
                 * @param {scope}: names of the xapp services that the consumer is trying to access
                 * @param {target_xapp_id}: instance id of the xapp service producer
                 * @param {key}: secret key [K]
                 * return void
                 */

};

} // app namespace defined
} // xrf namespace defined

#endif