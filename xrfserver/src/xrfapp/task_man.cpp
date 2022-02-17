/*
 * xApp authorization framework to be integrated into the reference RAN Intelligent Controller (RIC) of the 
 * Linux Foundation (LF) for distributing access tokens to xApps from an OAUTH 2.0 server using JSON web tokens
 * as the execution method of the tokens
 *
 *
 * ! file task_man.cpp
 *  \brief
 * \author: Tolga Omer Atalay
 * \Affiliation: VirginiaTech
 * \date: 2022
 * \email: tolgaoa@vt.edu
*/


#include "task_man.hpp"
#include <unistd.h>
#include <iostream>
#include <thread>

#include "logger.hpp"

using namespace xrf::app;

task_man::task_man(xrf_event& e) : event_sub_(e) {
	struct itimerspec its;

	sfd = timerfd_create(CLOCK_MONOTONIC, 0);

	its.it_value.tv_sec = 0;
	its.it_value.tv_nsec = 1000 * 1000;
	its.it_interval.tv_sec = its.it_value.tv_sec;
	its.it_interval.tv_nsec = its.it_value.tv_nsec;

	if( timerfd_settime(sfd, TFD_TIMER_ABSTIME, $its, NULL) == -1 ){
		Logger::nrf_app().error("Failed to set timer for task manager");	
	}
}

void task_man::run(){
	manage_task();
}

void task_man::manage_task(){
	uint64_t t = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();

	while(1){
		event_sub.task_tick(t);
		t++;
		wait_for_cycle();
	}
}

void task_manager::wait_for_cycle() {
	uint64_t exp;
	ssize_t res;

	if (sfd > 0) {
		res = read(sfd, &exp, sizeof(exp));
		if ((res < 0) || (res != sizeof(exp))) {
			Logger::nrf_app().error("Failed in task manager timer wait");
    }
  }

