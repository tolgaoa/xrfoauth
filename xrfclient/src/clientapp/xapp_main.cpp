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

#include "xapp_main.hpp"
#include <unistd.h>

using namespace xrf::app;

extern xapp_main* xapp_main_inst;
xrf_client* xrf_client_inst = nullptr;
xapp_msg* xapp_msg_inst = nullptr;

void xapp_main::register_with_xrf() {
	unsigned int wait = 10000;
	usleep(wait);
	//create_xappclient_profile();
	//send_xapp_registration_request();
}

void xapp_main::generate_uuid(){
	xappclient_instance_id = to_string(boost::uuids::random_generator()());
};


void xapp_main::create_xappclient_profile() {
	generate_uuid();

	//xappclient_instance_profile.set_xappclient_instance_id(xappclient_instance_id);
	//xappclient_instance_profile.set_xappclient_status("REGISTERED");
	//xappclient_instance_profile.set_xappclient_instance_name("xApp1");

}

/*std::string& xapp_main::create_auth_challenge(){
	
	//auto finalciphertext_s;
        unsigned char final_cipher_buf[FINAL_CIPHER_LEN];
        spdlog::info("Creating challenge");
        xapp_msg_inst->create_final_msg(final_cipher_buf);
        spdlog::info("Challenge created");

        spdlog::debug("Cast challenge from unsigned char to string");   
        std::ostringstream oss;
        for(int i = 0; i < FINAL_CIPHER_LEN; ++i) 
        {
              oss << std::hex << std::setw(2) << std::setfill('0') << +final_cipher_buf[i];
        }
        auto finalciphertext_s = oss.str();

        spdlog::debug(finalciphertext_s);

	return finalciphertext_s;

}
*/

void xapp_main::sendauth_to_xrf(const std::string& challenge, const std::string& xrfaddress){
	
	std::string str1 = "temp1";

	unsigned char final_cipher_buf[FINAL_CIPHER_LEN];

	std::string strtest;
	strtest.resize(1369);

	std::string str;
	spdlog::info("Creating challenge");
	//str = td::string& strxapp_msg_inst->create_final_msg(final_cipher_buf, str);
	str = xapp_msg_inst->create_final_msg(final_cipher_buf);
	//str.resize(1369);
	strtest.replace(0, 1369, str);
	spdlog::info("Challenge created");
	spdlog::debug("String is:");
	spdlog::debug(str);

	/*spdlog::debug("Cast challenge from unsigned char to string");	
	std::ostringstream oss;
	for(int i = 0; i < FINAL_CIPHER_LEN; ++i) 
	{
	      oss << std::hex << std::setw(2) << std::setfill('0') << +final_cipher_buf[i];
	}
	auto str = oss.str();	
	
	spdlog::debug(str);
	*/

	std::string str2 = "1234567890qwertyuiopasdfghjklzxcvbnm1234567890qwertyuiopasdfghjklzxcvbnm1234567890qwertyuiopasdfghjklzxcvbnm1234567890qwertyuiopasdfghjklzxcvbnm1234567890qwertyuiopasdfghjklzxcvbnm1234567890qwertyuiopasdfghjklzxcvbnm1234567890qwertyuiopasdfghjklzxcvbnm1234567890qwertyuiopasdfghjklzxcvbnm1234567890qwertyuiopasdfghjklzxcvbnm1234567890qwertyuiopasdfghjklzxcvbnm1234567890qwertyuiopasdfghjklzxcvbnm1234567890qwertyuiopasdfghjklzxcvbnm1234567890qwertyuiopasdfghjklzxcvbnm1234567890qwertyuiopasdfghjklzxcvbnm1234567890qwertyuiopasdfghjklzxcvbnm1234567890qwertyuiopasdfghjklzxcvbnm1234567890qwertyuiopasdfghjklzxcvbnm1234567890qwertyuiopasdfghjklzxcvbnm1234567890qwertyuiopasdfghjklzxcvbnm1234567890qwertyuiopasdfghjklzxcvbnm1234567890qwertyuiopasdfghjklzxcvbnm1234567890qwertyuiopasdfghjklzxcvbnm1234567890qwertyuiopasdfghjklzxcvbnm1234567890qwertyuiopasdfghjklzxcvbnm1234567890qwertyuiopasdfghjklzxcvbnm1234567890qwertyuiopasdfghjklzxcvbnm1234567890qwertyuiopasdfghjklzxcvbnm1234567890qwertyuiopasdfghjklzxcvbnm1234567890qwertyuiopasdfghjklzxcvbnm1234567890qwertyuiopasdfghjklzxcvbnm1234567890qwertyuiopasdfghjklzxcvbnm1234567890qwertyuiopasdfghjklzxcvbnm1234567890qwertyuiopasdfghjklzxcvbnm1234567890qwertyuiopasdfghjklzxcvbnm1234567890qwertyuiopasdfghjklzxcvbnm1234567890qwertyuiopasdfghjklzxcvbnm1234567890qw+ertyuiopasdfghjklzxcvbn/+m1234567890qwertyuiopasdfghjklzxcvbn//m1234567890qwertyuiopasdfghjklzxcvbnm==90qw+ertyuiopasdfghjklzxcvbn/+m1234567890qwertyuiopasdfghjklzxcvbn//m1234567890qwertyuiopasdfghjklzxcvbnm==90qw+ertyuiopasdfghjklzxcvbn/+m1234567890qwertyuiopasdfghjklzxcvbn//m1234567890qwertyuiopasdfghjklzxcvbnm==90qw+ertyuiopasdfghjklzxcvbn/+m1234567890qwertyuiopasdfghjklzxcvbn//m1234567890qwertyuiopasdfghjklzxcvbnm==90qw+ertyuiopasdfghjklzxcvbn/+m1234567890qwertyuiopasdfghjklzxcvbn//m1234567890qwertyuiopasdfghjklzxcvbnm==90qw+ertyuiopasdfghjklzxcvbn/+m1234567890qwertyuiopasdfghjklzxcvbn//m1234567890qwertyuiopasdfghjklzxcvbnm==90qw+ertyuiopasdfghjklzxcvbn/+m1234567890qwertyuiopasdfghjklzxcvbn//m1234567890qwertyuiopasdfghjklzxcvbnm==90qw+ertyuiopasdfghjklzxcvbn/+m1234567890qwertyuiopasdfghjklzxcvbn//m1234567890qwertyuiopasdfghjklzxcvbnm==90qw+ertyuiopasdfghjklzxcvbn/+m1234567890qwertyuiopasdfghjklzxcvbn//m1234567890qwertyuiopasdfghjklzxcvbnm==90qw+ertyuiopasdfghjklzxcvbn/+m1234567890qwertyuiopasdfghjklzxcvbn//m1234567890qwertyuiopasdfghjklzxcvbnm==90qw+ertyuiopasdfghjklzxcvbn/+m1234567890qwertyuiopasdfghjklzxcvbn//m1234567890qwertyuiopasdfghjklzxcvbnm==90qw+ertyuiopasdfghjklzxcvbn/+m1234567890qwertyuiopasdfghjklzxcvbn//m1234567890qwertyuiopasdfghjklzxcvbnm==90qw+ertyuiopasdfghjklzxcvbn/+m1234567890qwertyuiopasdfghjklzxcvbn//m1234567890qwertyuiopasdfghjklzxcvbnm==";
	
	std::string str3 = "WzkHqzmTdsPUyNPY4oDmqPPoECwkyGoXNES39xeTRlM6b1BIE3kpR1HYs/98BUJ4rm60db4yi3/1zYOcIE9xQBodCSPaN+it1GzjTAqj7riF8pBZeO1mpEHsTKOzB7McC/8FgyMNjvqxVjjbs5EhXeaFpqVEGDKCgEeBE+gZV98pSjd8g0lPbd3NsU2kQAm21z43Jb6DvZ9aLrmi3xpAqbSB60aRncMvRGc7vlUtDeQEw602mX4vWy+z6l6lHxJP0H3oI8UHC8CALmPpSvFf9N8K+HE+cziYQVTODK3v683mc526p9LYHPMxPGsn9nffsQBbWgVDJ1R/KPfJpfu5iW4VSBtMhrhOURDuc8l+Ie6Pu5ruN8y59AN80WiQixQFN/5i6bfrmF870vnXcy/aT0RpmQxq9Jol0d4MKGxS8Ye7Ij2KG3xhEgBb5RGH7htHQr88vcXGUWGgOPSMup2kUzMDlTyePLJCnbtYIbloxmZIUcsv+Ir1gIAlSvCyOVWfmEUrQz5/WdsXMvfiaTHXVgNpUUfLXW+o5qbdJqjqWzPxzILmxZuLibE8EudcUJGX7qq11dNIQlxQBCF4ZXjrFCuCbSHk1ij3oZDp5zdYsEKw4GFtw0rkKdq0tX/U0v09VXxXmSnHd6lAkZEaF9PvL5Zqt3+yZ9D3HrPbNvHlLIZgLI+fmsVPeJxFiSETS+vytD1ewuke+UIx6ghji9lUfH/nmdc/9W06VqSjrBVY2i/dH+akqGgcP9Jy3ZbMmHWtka76V6IJOaQMTlbx8nub0IXYbuXnZavSwMZyBZiK1bmr9ZjXVMwt6QZdgPCikfUfreiNH2ZjhMe2Vcw05yQS89sfOkM7ZgvR8UPpk2/i8gwW04DlJy+J6tT/d0ZHJGWKXGjO5WAAWuJ99uQ9kxlLJC3f+yGAG9WuOzMJlIowUQYu8WKBNsT3E1BRff9URAOyduGJYFToMytElrVBvdJ1B3Rvc4alVe0THODF3yhdwkIzETLhScBF7XicGGkHMlrUgLxC+dU7H1S4F7NgCA/jExFd242b60t0Agmf3QUd9sts6pZQ0NUCZA6P/LbWH0nE7no8Sc+WjjvQUG8Y02u+fi9S5BfIThr2hYiNDL2vPVBzCbVA/NM0so5Rydcakg/OXCyvDM5976GFnwRugnLqU+kh/rnK9q8skSv36Xq422olkWGU85hVHj0sdVfSZkvHWoa7zhlEbP67bsfVGtaMKxVEneWuXXv32eMof2ezerb8p2xb4xnOm3kK+DjP1cV4ATkTrt/1ZVdcjEUDvnhpy3+9p8ZN2mWUXwvl9BensHQkl2Gh9qSNGr1qOZmFLpTL0/4kTbwSMSWfo3cLV6YEAQ==";
	
	std::string str4 = "M/rRXxgXB7V7zGxMs7e8GLuj6sU4YnstG5om9KDTOZyYczTBGuxqekTj2pkKcBeNSE6YsU6hk2nMODXr1/iJKSA0BduUsEEc+PHMUqblLYEJOy1V5ZkrDlAWepRa6neJMgkqJtv+GsyQ8X9WXsztqjmaCbKYRZBQ0yMcsCISiRC31DgxFbh1rKgm+WyL6MnVFPiOZl+sIW+G+BoFeCoIBvy5/GSct/FDuU6o3OT05+XUp9BaK1d/ULp1C4sM4XNqStrIGNzFJSsQNX7DDmx+7k8BKd3EQS1b8uQsLcO35RhH5VcStqPHgj9iC9NoJ/GiHR6pOBa5mzoZHk2Q+vvFQu0s8AuQKiAL6tec/9uw/AqJxRVdWnFfywYTHJYmXZXUrWi6lhZiOU0XoKeUx15N0YudmC2Q+yRc0XnhStdy5UMp1zgLofuSwWinCnk2YPI/OJRslIIEmtwG+QCsR2Fsd51tLTi12nTFPGg/GWtulpR4mNbqAbiCx6IcZ1uBXH9kE8qpHAUz6EwbrsVURwpfhG4p7E3ifp+nMLlFt1pj2fDhBFE42Z2LPbjCQfXCKZ1xg6Yljb3nk7J5SBUuLkLfJKriwP1soWFADAQJMMpAcTCvRy1+lUKj9MQnv80P3RbKG1oKC5p39z7MQyT7Urb0X4FrYuJncne6oguYYX2a4zgeqNpaQUxE7p96jHH03JpE71YBWqL1dE3B/rj6pwS8I+E55BNl8vn4uRi5Ts9Zm3Ovgc9VmkGB8Wrfm1xnd1I/NaPbFNrlRXyoXfTQrQUsJp6SzfIYu551wDKJGadzOLNeMDcMeZVYy8Ixqnx0mJ2G4YGZ63VsE9LueXmqvP6q6loVKqo5/2rvxwvc1vDN3qSQvhiYUO2QmfGMWznHnC55Sj6d5WcB6iNlwnoJOZ9HtARMzqdOYs05QMiShpdjo0yx4qZOFbJypLjNsBway3Ky4Zpk6RdbtqeIfJrwibpFM5qtdBslU0HnajqSA0faD2m/86Hz0Y6scxKuSk3rdAdHKACGk5kgjiZo5WhHk+rQqBSQbFmyYoR6naWc4Sj10ltfu3zpBt+3KbWYsyuSKAmEwCuWJyRWxXc/XSsZKdeSlW/yLCyFSRYbaPBjGoEK5zYI6JIujDRjzCvaTkBq5OFnQgTOz6ZdKuepS3XaUWv1hRSXKf6qfzZL46yLm55Xo6wDNYvVb1C+UyWXoTi4IXNH1Naz/XqZYPisUnT0eKD3EREVHNpFTgqirb4NtKIQ9BPslQt072fP0OvLTBwkqw27WY8robUHUGoyCSAJKqrnYUt+n1NTKTQrYkgxKDdKuLjXYAfULy94RSmB2sxm4rL1x/LsJUg+wvwbdC9NCyQMrA==";


	spdlog::info("Creating Client");

	std::cout << str4 << std::endl << std::endl << std::endl << str4.length() << " " << str4.capacity() << std::endl;
	std::cout << strtest << std::endl << std::endl << std::endl << str.length() << " " << str.capacity() << std::endl;
	xrf_client_inst->curl_create_handle(xrfaddress, str4, str1, 1);
	xrf_client_inst->curl_create_handle(xrfaddress, strtest, str1, 1);
	spdlog::info("Client Created");
}


