#include "pistache/endpoint.h"
#include "pistache/http.h"
#include "pistache/router.h"

#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <iostream>
#include <thread>

#include "xappclient_main.hpp"

using namespace xappclient;

xappclient_main* xappclient_main_inst = nullptr;


int main(int argc, char** argv){

	xappclient_main_inst->register_with_xrf();

	return 0;


}
