#include "pistache/endpoint.h"
#include "pistache/http.h"
#include "pistache/router.h"

#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <iostream>
#include <thread>


using namespace xappclient::app;

xappclient* xappclient_inst = nullptr;


int main(int argc, char** argv){

	xappclient_inst-register_with_xrf();

	return 0;


}
