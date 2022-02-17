/*
 * xApp authorization framework to be integrated into the reference RAN Intelligent Controller (RIC) of the 
 * Linux Foundation (LF) for distributing access tokens to xApps from an OAUTH 2.0 server using JSON web tokens
 * as the execution method of the tokens
 *
 *
 * ! file task_man.hpp
 *  \brief
 * \author: Tolga Omer Atalay
 * \Affiliation: VirginiaTech
 * \date: 2022
 * \email: tolgaoa@vt.edu
*/

#ifndef FILE_TASK_MAN_HPP_SEEN
#define FILE_TASK_MAN_HPP_SEEN

#include "nrf_event.hpp"
#include "linux/types.h"
#include "sys/timerfd.h"

using namespace xrf::app;

namespace xrf{
namespace app{

class xrf_event;
class task_man {
	public:
		task_man{xrf_event& e};

		void manage_task();
		/*
		 * manage the task object
		 */
		
		void run();
		/*
		 * run the the task object
		 */
		
	private:
		void wait();
		/*
		 * wait 1ms between tasks
		 */

		xrf_event& event_sub_;
		int sfd;

};
}
}


#endif

