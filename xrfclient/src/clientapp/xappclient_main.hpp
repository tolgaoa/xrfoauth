/*
 * Client side of the xApp authorization framework to be integrated into the reference RAN Intelligent 
 * Controller (RIC) of the Linux Foundation (LF) for distributing access tokens to xApps from an 
 * OAUTH 2.0 server using JSON web tokens as the execution method of the tokens
 *
 *
 * ! file xappclient_main.cpp
 *  \brief
 * \author: Tolga Omer Atalay
 * \Affiliation: VirginiaTech
 * \date: 2022
 * \email: tolgaoa@vt.edu
*/

#ifndef FILE_XAPPCLIENT_MAIN_HPP_SEEN
#define FILE_XAPPCLIENT_MAIN_HPP_SEEN

#include <boost/thread/future.hpp>
#include <future>
#include <map>
#include <set>
#include <shared_mutex>
#include <string>
#include <thread>

namespace xappclient{

class xappclient_main {
	public:
		explicit xappclient_main();
		xappclient_main(xappclient_main const&) = delete;
		virtual ~xappclient_main();

		void operator=(xappclient_main const&) = delete;
		
		void register_with_xrf();
		/*
		 * Register the xapp with the XRF server
		 */

		void create_xappclient_profile();
		/*
		 *  Create a profile for the xapp instance
		 */

		void generate_uuid();
		/*
		 * create a random string id for the xapp instance
		 */
};


}



#endif
