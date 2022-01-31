/*
 * xApp authorization framework to be integrated into the reference RAN Intelligent Controller (RIC) of the 
 * Linux Foundation (LF) for distributing access tokens to xApps from an OAUTH 2.0 server using JSON web tokens
 * as the execution method of the tokens
 *
 *
 * ! file xrf_sig.hpp
 *  \brief
 * \author: Tolga Omer Atalay
 * \Affiliation: VirginiaTech
 * \date: 2022
 * \email: tolgaoa@vt.edu
*/

#ifndef FILE_XRF_SIG_HPP_SEEN
#define FILE_XRF_SIG_HPP_SEEN

#include <boost/signals2.hpp>

namespace bs2 = boost::signals2;

namespace xrf{
namespace app{

class xrf_profile; // TODO

typedef bs2::signal_type<void(uint64_t), bs2::keywords::mutex_type<bs2::dummy_mutex>>::type task_sig_t;

typedef bs2::signal_type<void(const std::string&), bs2::keywords::mutex_type<bs2::dummy_mutex>>::type xapp_curr_sig_t;

typedef bs2::signal_type<void(const std::string&), bs2::keywords::mutex_type<bs2::dummy_mutex>>::type xapp_curr_change_sig_t;


}
}


#endif





















