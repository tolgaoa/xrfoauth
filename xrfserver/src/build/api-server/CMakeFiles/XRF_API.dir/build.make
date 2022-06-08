# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.23

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/taport/xrfoauth/xrfserver/src

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/taport/xrfoauth/xrfserver/src/build

# Include any dependencies generated for this target.
include api-server/CMakeFiles/XRF_API.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include api-server/CMakeFiles/XRF_API.dir/compiler_depend.make

# Include the progress variables for this target.
include api-server/CMakeFiles/XRF_API.dir/progress.make

# Include the compile flags for this target's objects.
include api-server/CMakeFiles/XRF_API.dir/flags.make

api-server/CMakeFiles/XRF_API.dir/api/AccessTokenRequestApi.cpp.o: api-server/CMakeFiles/XRF_API.dir/flags.make
api-server/CMakeFiles/XRF_API.dir/api/AccessTokenRequestApi.cpp.o: ../api-server/api/AccessTokenRequestApi.cpp
api-server/CMakeFiles/XRF_API.dir/api/AccessTokenRequestApi.cpp.o: api-server/CMakeFiles/XRF_API.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/taport/xrfoauth/xrfserver/src/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object api-server/CMakeFiles/XRF_API.dir/api/AccessTokenRequestApi.cpp.o"
	cd /home/taport/xrfoauth/xrfserver/src/build/api-server && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT api-server/CMakeFiles/XRF_API.dir/api/AccessTokenRequestApi.cpp.o -MF CMakeFiles/XRF_API.dir/api/AccessTokenRequestApi.cpp.o.d -o CMakeFiles/XRF_API.dir/api/AccessTokenRequestApi.cpp.o -c /home/taport/xrfoauth/xrfserver/src/api-server/api/AccessTokenRequestApi.cpp

api-server/CMakeFiles/XRF_API.dir/api/AccessTokenRequestApi.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/XRF_API.dir/api/AccessTokenRequestApi.cpp.i"
	cd /home/taport/xrfoauth/xrfserver/src/build/api-server && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/taport/xrfoauth/xrfserver/src/api-server/api/AccessTokenRequestApi.cpp > CMakeFiles/XRF_API.dir/api/AccessTokenRequestApi.cpp.i

api-server/CMakeFiles/XRF_API.dir/api/AccessTokenRequestApi.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/XRF_API.dir/api/AccessTokenRequestApi.cpp.s"
	cd /home/taport/xrfoauth/xrfserver/src/build/api-server && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/taport/xrfoauth/xrfserver/src/api-server/api/AccessTokenRequestApi.cpp -o CMakeFiles/XRF_API.dir/api/AccessTokenRequestApi.cpp.s

api-server/CMakeFiles/XRF_API.dir/api/InitialAuthenticationRequestApi.cpp.o: api-server/CMakeFiles/XRF_API.dir/flags.make
api-server/CMakeFiles/XRF_API.dir/api/InitialAuthenticationRequestApi.cpp.o: ../api-server/api/InitialAuthenticationRequestApi.cpp
api-server/CMakeFiles/XRF_API.dir/api/InitialAuthenticationRequestApi.cpp.o: api-server/CMakeFiles/XRF_API.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/taport/xrfoauth/xrfserver/src/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object api-server/CMakeFiles/XRF_API.dir/api/InitialAuthenticationRequestApi.cpp.o"
	cd /home/taport/xrfoauth/xrfserver/src/build/api-server && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT api-server/CMakeFiles/XRF_API.dir/api/InitialAuthenticationRequestApi.cpp.o -MF CMakeFiles/XRF_API.dir/api/InitialAuthenticationRequestApi.cpp.o.d -o CMakeFiles/XRF_API.dir/api/InitialAuthenticationRequestApi.cpp.o -c /home/taport/xrfoauth/xrfserver/src/api-server/api/InitialAuthenticationRequestApi.cpp

api-server/CMakeFiles/XRF_API.dir/api/InitialAuthenticationRequestApi.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/XRF_API.dir/api/InitialAuthenticationRequestApi.cpp.i"
	cd /home/taport/xrfoauth/xrfserver/src/build/api-server && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/taport/xrfoauth/xrfserver/src/api-server/api/InitialAuthenticationRequestApi.cpp > CMakeFiles/XRF_API.dir/api/InitialAuthenticationRequestApi.cpp.i

api-server/CMakeFiles/XRF_API.dir/api/InitialAuthenticationRequestApi.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/XRF_API.dir/api/InitialAuthenticationRequestApi.cpp.s"
	cd /home/taport/xrfoauth/xrfserver/src/build/api-server && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/taport/xrfoauth/xrfserver/src/api-server/api/InitialAuthenticationRequestApi.cpp -o CMakeFiles/XRF_API.dir/api/InitialAuthenticationRequestApi.cpp.s

api-server/CMakeFiles/XRF_API.dir/impl/AccessTokenRequestApiImpl.cpp.o: api-server/CMakeFiles/XRF_API.dir/flags.make
api-server/CMakeFiles/XRF_API.dir/impl/AccessTokenRequestApiImpl.cpp.o: ../api-server/impl/AccessTokenRequestApiImpl.cpp
api-server/CMakeFiles/XRF_API.dir/impl/AccessTokenRequestApiImpl.cpp.o: api-server/CMakeFiles/XRF_API.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/taport/xrfoauth/xrfserver/src/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object api-server/CMakeFiles/XRF_API.dir/impl/AccessTokenRequestApiImpl.cpp.o"
	cd /home/taport/xrfoauth/xrfserver/src/build/api-server && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT api-server/CMakeFiles/XRF_API.dir/impl/AccessTokenRequestApiImpl.cpp.o -MF CMakeFiles/XRF_API.dir/impl/AccessTokenRequestApiImpl.cpp.o.d -o CMakeFiles/XRF_API.dir/impl/AccessTokenRequestApiImpl.cpp.o -c /home/taport/xrfoauth/xrfserver/src/api-server/impl/AccessTokenRequestApiImpl.cpp

api-server/CMakeFiles/XRF_API.dir/impl/AccessTokenRequestApiImpl.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/XRF_API.dir/impl/AccessTokenRequestApiImpl.cpp.i"
	cd /home/taport/xrfoauth/xrfserver/src/build/api-server && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/taport/xrfoauth/xrfserver/src/api-server/impl/AccessTokenRequestApiImpl.cpp > CMakeFiles/XRF_API.dir/impl/AccessTokenRequestApiImpl.cpp.i

api-server/CMakeFiles/XRF_API.dir/impl/AccessTokenRequestApiImpl.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/XRF_API.dir/impl/AccessTokenRequestApiImpl.cpp.s"
	cd /home/taport/xrfoauth/xrfserver/src/build/api-server && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/taport/xrfoauth/xrfserver/src/api-server/impl/AccessTokenRequestApiImpl.cpp -o CMakeFiles/XRF_API.dir/impl/AccessTokenRequestApiImpl.cpp.s

api-server/CMakeFiles/XRF_API.dir/impl/InitialAuthenticationRequestApiImpl.cpp.o: api-server/CMakeFiles/XRF_API.dir/flags.make
api-server/CMakeFiles/XRF_API.dir/impl/InitialAuthenticationRequestApiImpl.cpp.o: ../api-server/impl/InitialAuthenticationRequestApiImpl.cpp
api-server/CMakeFiles/XRF_API.dir/impl/InitialAuthenticationRequestApiImpl.cpp.o: api-server/CMakeFiles/XRF_API.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/taport/xrfoauth/xrfserver/src/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building CXX object api-server/CMakeFiles/XRF_API.dir/impl/InitialAuthenticationRequestApiImpl.cpp.o"
	cd /home/taport/xrfoauth/xrfserver/src/build/api-server && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT api-server/CMakeFiles/XRF_API.dir/impl/InitialAuthenticationRequestApiImpl.cpp.o -MF CMakeFiles/XRF_API.dir/impl/InitialAuthenticationRequestApiImpl.cpp.o.d -o CMakeFiles/XRF_API.dir/impl/InitialAuthenticationRequestApiImpl.cpp.o -c /home/taport/xrfoauth/xrfserver/src/api-server/impl/InitialAuthenticationRequestApiImpl.cpp

api-server/CMakeFiles/XRF_API.dir/impl/InitialAuthenticationRequestApiImpl.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/XRF_API.dir/impl/InitialAuthenticationRequestApiImpl.cpp.i"
	cd /home/taport/xrfoauth/xrfserver/src/build/api-server && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/taport/xrfoauth/xrfserver/src/api-server/impl/InitialAuthenticationRequestApiImpl.cpp > CMakeFiles/XRF_API.dir/impl/InitialAuthenticationRequestApiImpl.cpp.i

api-server/CMakeFiles/XRF_API.dir/impl/InitialAuthenticationRequestApiImpl.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/XRF_API.dir/impl/InitialAuthenticationRequestApiImpl.cpp.s"
	cd /home/taport/xrfoauth/xrfserver/src/build/api-server && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/taport/xrfoauth/xrfserver/src/api-server/impl/InitialAuthenticationRequestApiImpl.cpp -o CMakeFiles/XRF_API.dir/impl/InitialAuthenticationRequestApiImpl.cpp.s

api-server/CMakeFiles/XRF_API.dir/model/AccessTokenClaims.cpp.o: api-server/CMakeFiles/XRF_API.dir/flags.make
api-server/CMakeFiles/XRF_API.dir/model/AccessTokenClaims.cpp.o: ../api-server/model/AccessTokenClaims.cpp
api-server/CMakeFiles/XRF_API.dir/model/AccessTokenClaims.cpp.o: api-server/CMakeFiles/XRF_API.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/taport/xrfoauth/xrfserver/src/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building CXX object api-server/CMakeFiles/XRF_API.dir/model/AccessTokenClaims.cpp.o"
	cd /home/taport/xrfoauth/xrfserver/src/build/api-server && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT api-server/CMakeFiles/XRF_API.dir/model/AccessTokenClaims.cpp.o -MF CMakeFiles/XRF_API.dir/model/AccessTokenClaims.cpp.o.d -o CMakeFiles/XRF_API.dir/model/AccessTokenClaims.cpp.o -c /home/taport/xrfoauth/xrfserver/src/api-server/model/AccessTokenClaims.cpp

api-server/CMakeFiles/XRF_API.dir/model/AccessTokenClaims.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/XRF_API.dir/model/AccessTokenClaims.cpp.i"
	cd /home/taport/xrfoauth/xrfserver/src/build/api-server && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/taport/xrfoauth/xrfserver/src/api-server/model/AccessTokenClaims.cpp > CMakeFiles/XRF_API.dir/model/AccessTokenClaims.cpp.i

api-server/CMakeFiles/XRF_API.dir/model/AccessTokenClaims.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/XRF_API.dir/model/AccessTokenClaims.cpp.s"
	cd /home/taport/xrfoauth/xrfserver/src/build/api-server && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/taport/xrfoauth/xrfserver/src/api-server/model/AccessTokenClaims.cpp -o CMakeFiles/XRF_API.dir/model/AccessTokenClaims.cpp.s

api-server/CMakeFiles/XRF_API.dir/model/AccessTokenErr.cpp.o: api-server/CMakeFiles/XRF_API.dir/flags.make
api-server/CMakeFiles/XRF_API.dir/model/AccessTokenErr.cpp.o: ../api-server/model/AccessTokenErr.cpp
api-server/CMakeFiles/XRF_API.dir/model/AccessTokenErr.cpp.o: api-server/CMakeFiles/XRF_API.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/taport/xrfoauth/xrfserver/src/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Building CXX object api-server/CMakeFiles/XRF_API.dir/model/AccessTokenErr.cpp.o"
	cd /home/taport/xrfoauth/xrfserver/src/build/api-server && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT api-server/CMakeFiles/XRF_API.dir/model/AccessTokenErr.cpp.o -MF CMakeFiles/XRF_API.dir/model/AccessTokenErr.cpp.o.d -o CMakeFiles/XRF_API.dir/model/AccessTokenErr.cpp.o -c /home/taport/xrfoauth/xrfserver/src/api-server/model/AccessTokenErr.cpp

api-server/CMakeFiles/XRF_API.dir/model/AccessTokenErr.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/XRF_API.dir/model/AccessTokenErr.cpp.i"
	cd /home/taport/xrfoauth/xrfserver/src/build/api-server && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/taport/xrfoauth/xrfserver/src/api-server/model/AccessTokenErr.cpp > CMakeFiles/XRF_API.dir/model/AccessTokenErr.cpp.i

api-server/CMakeFiles/XRF_API.dir/model/AccessTokenErr.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/XRF_API.dir/model/AccessTokenErr.cpp.s"
	cd /home/taport/xrfoauth/xrfserver/src/build/api-server && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/taport/xrfoauth/xrfserver/src/api-server/model/AccessTokenErr.cpp -o CMakeFiles/XRF_API.dir/model/AccessTokenErr.cpp.s

api-server/CMakeFiles/XRF_API.dir/model/AccessTokenRsp.cpp.o: api-server/CMakeFiles/XRF_API.dir/flags.make
api-server/CMakeFiles/XRF_API.dir/model/AccessTokenRsp.cpp.o: ../api-server/model/AccessTokenRsp.cpp
api-server/CMakeFiles/XRF_API.dir/model/AccessTokenRsp.cpp.o: api-server/CMakeFiles/XRF_API.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/taport/xrfoauth/xrfserver/src/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_7) "Building CXX object api-server/CMakeFiles/XRF_API.dir/model/AccessTokenRsp.cpp.o"
	cd /home/taport/xrfoauth/xrfserver/src/build/api-server && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT api-server/CMakeFiles/XRF_API.dir/model/AccessTokenRsp.cpp.o -MF CMakeFiles/XRF_API.dir/model/AccessTokenRsp.cpp.o.d -o CMakeFiles/XRF_API.dir/model/AccessTokenRsp.cpp.o -c /home/taport/xrfoauth/xrfserver/src/api-server/model/AccessTokenRsp.cpp

api-server/CMakeFiles/XRF_API.dir/model/AccessTokenRsp.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/XRF_API.dir/model/AccessTokenRsp.cpp.i"
	cd /home/taport/xrfoauth/xrfserver/src/build/api-server && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/taport/xrfoauth/xrfserver/src/api-server/model/AccessTokenRsp.cpp > CMakeFiles/XRF_API.dir/model/AccessTokenRsp.cpp.i

api-server/CMakeFiles/XRF_API.dir/model/AccessTokenRsp.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/XRF_API.dir/model/AccessTokenRsp.cpp.s"
	cd /home/taport/xrfoauth/xrfserver/src/build/api-server && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/taport/xrfoauth/xrfserver/src/api-server/model/AccessTokenRsp.cpp -o CMakeFiles/XRF_API.dir/model/AccessTokenRsp.cpp.s

api-server/CMakeFiles/XRF_API.dir/model/Helpers.cpp.o: api-server/CMakeFiles/XRF_API.dir/flags.make
api-server/CMakeFiles/XRF_API.dir/model/Helpers.cpp.o: ../api-server/model/Helpers.cpp
api-server/CMakeFiles/XRF_API.dir/model/Helpers.cpp.o: api-server/CMakeFiles/XRF_API.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/taport/xrfoauth/xrfserver/src/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_8) "Building CXX object api-server/CMakeFiles/XRF_API.dir/model/Helpers.cpp.o"
	cd /home/taport/xrfoauth/xrfserver/src/build/api-server && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT api-server/CMakeFiles/XRF_API.dir/model/Helpers.cpp.o -MF CMakeFiles/XRF_API.dir/model/Helpers.cpp.o.d -o CMakeFiles/XRF_API.dir/model/Helpers.cpp.o -c /home/taport/xrfoauth/xrfserver/src/api-server/model/Helpers.cpp

api-server/CMakeFiles/XRF_API.dir/model/Helpers.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/XRF_API.dir/model/Helpers.cpp.i"
	cd /home/taport/xrfoauth/xrfserver/src/build/api-server && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/taport/xrfoauth/xrfserver/src/api-server/model/Helpers.cpp > CMakeFiles/XRF_API.dir/model/Helpers.cpp.i

api-server/CMakeFiles/XRF_API.dir/model/Helpers.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/XRF_API.dir/model/Helpers.cpp.s"
	cd /home/taport/xrfoauth/xrfserver/src/build/api-server && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/taport/xrfoauth/xrfserver/src/api-server/model/Helpers.cpp -o CMakeFiles/XRF_API.dir/model/Helpers.cpp.s

api-server/CMakeFiles/XRF_API.dir/model/InitAuthErr.cpp.o: api-server/CMakeFiles/XRF_API.dir/flags.make
api-server/CMakeFiles/XRF_API.dir/model/InitAuthErr.cpp.o: ../api-server/model/InitAuthErr.cpp
api-server/CMakeFiles/XRF_API.dir/model/InitAuthErr.cpp.o: api-server/CMakeFiles/XRF_API.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/taport/xrfoauth/xrfserver/src/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_9) "Building CXX object api-server/CMakeFiles/XRF_API.dir/model/InitAuthErr.cpp.o"
	cd /home/taport/xrfoauth/xrfserver/src/build/api-server && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT api-server/CMakeFiles/XRF_API.dir/model/InitAuthErr.cpp.o -MF CMakeFiles/XRF_API.dir/model/InitAuthErr.cpp.o.d -o CMakeFiles/XRF_API.dir/model/InitAuthErr.cpp.o -c /home/taport/xrfoauth/xrfserver/src/api-server/model/InitAuthErr.cpp

api-server/CMakeFiles/XRF_API.dir/model/InitAuthErr.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/XRF_API.dir/model/InitAuthErr.cpp.i"
	cd /home/taport/xrfoauth/xrfserver/src/build/api-server && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/taport/xrfoauth/xrfserver/src/api-server/model/InitAuthErr.cpp > CMakeFiles/XRF_API.dir/model/InitAuthErr.cpp.i

api-server/CMakeFiles/XRF_API.dir/model/InitAuthErr.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/XRF_API.dir/model/InitAuthErr.cpp.s"
	cd /home/taport/xrfoauth/xrfserver/src/build/api-server && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/taport/xrfoauth/xrfserver/src/api-server/model/InitAuthErr.cpp -o CMakeFiles/XRF_API.dir/model/InitAuthErr.cpp.s

api-server/CMakeFiles/XRF_API.dir/model/InitAuthReq.cpp.o: api-server/CMakeFiles/XRF_API.dir/flags.make
api-server/CMakeFiles/XRF_API.dir/model/InitAuthReq.cpp.o: ../api-server/model/InitAuthReq.cpp
api-server/CMakeFiles/XRF_API.dir/model/InitAuthReq.cpp.o: api-server/CMakeFiles/XRF_API.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/taport/xrfoauth/xrfserver/src/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_10) "Building CXX object api-server/CMakeFiles/XRF_API.dir/model/InitAuthReq.cpp.o"
	cd /home/taport/xrfoauth/xrfserver/src/build/api-server && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT api-server/CMakeFiles/XRF_API.dir/model/InitAuthReq.cpp.o -MF CMakeFiles/XRF_API.dir/model/InitAuthReq.cpp.o.d -o CMakeFiles/XRF_API.dir/model/InitAuthReq.cpp.o -c /home/taport/xrfoauth/xrfserver/src/api-server/model/InitAuthReq.cpp

api-server/CMakeFiles/XRF_API.dir/model/InitAuthReq.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/XRF_API.dir/model/InitAuthReq.cpp.i"
	cd /home/taport/xrfoauth/xrfserver/src/build/api-server && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/taport/xrfoauth/xrfserver/src/api-server/model/InitAuthReq.cpp > CMakeFiles/XRF_API.dir/model/InitAuthReq.cpp.i

api-server/CMakeFiles/XRF_API.dir/model/InitAuthReq.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/XRF_API.dir/model/InitAuthReq.cpp.s"
	cd /home/taport/xrfoauth/xrfserver/src/build/api-server && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/taport/xrfoauth/xrfserver/src/api-server/model/InitAuthReq.cpp -o CMakeFiles/XRF_API.dir/model/InitAuthReq.cpp.s

api-server/CMakeFiles/XRF_API.dir/model/InitAuthRsp.cpp.o: api-server/CMakeFiles/XRF_API.dir/flags.make
api-server/CMakeFiles/XRF_API.dir/model/InitAuthRsp.cpp.o: ../api-server/model/InitAuthRsp.cpp
api-server/CMakeFiles/XRF_API.dir/model/InitAuthRsp.cpp.o: api-server/CMakeFiles/XRF_API.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/taport/xrfoauth/xrfserver/src/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_11) "Building CXX object api-server/CMakeFiles/XRF_API.dir/model/InitAuthRsp.cpp.o"
	cd /home/taport/xrfoauth/xrfserver/src/build/api-server && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT api-server/CMakeFiles/XRF_API.dir/model/InitAuthRsp.cpp.o -MF CMakeFiles/XRF_API.dir/model/InitAuthRsp.cpp.o.d -o CMakeFiles/XRF_API.dir/model/InitAuthRsp.cpp.o -c /home/taport/xrfoauth/xrfserver/src/api-server/model/InitAuthRsp.cpp

api-server/CMakeFiles/XRF_API.dir/model/InitAuthRsp.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/XRF_API.dir/model/InitAuthRsp.cpp.i"
	cd /home/taport/xrfoauth/xrfserver/src/build/api-server && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/taport/xrfoauth/xrfserver/src/api-server/model/InitAuthRsp.cpp > CMakeFiles/XRF_API.dir/model/InitAuthRsp.cpp.i

api-server/CMakeFiles/XRF_API.dir/model/InitAuthRsp.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/XRF_API.dir/model/InitAuthRsp.cpp.s"
	cd /home/taport/xrfoauth/xrfserver/src/build/api-server && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/taport/xrfoauth/xrfserver/src/api-server/model/InitAuthRsp.cpp -o CMakeFiles/XRF_API.dir/model/InitAuthRsp.cpp.s

api-server/CMakeFiles/XRF_API.dir/model/ProblemDetails.cpp.o: api-server/CMakeFiles/XRF_API.dir/flags.make
api-server/CMakeFiles/XRF_API.dir/model/ProblemDetails.cpp.o: ../api-server/model/ProblemDetails.cpp
api-server/CMakeFiles/XRF_API.dir/model/ProblemDetails.cpp.o: api-server/CMakeFiles/XRF_API.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/taport/xrfoauth/xrfserver/src/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_12) "Building CXX object api-server/CMakeFiles/XRF_API.dir/model/ProblemDetails.cpp.o"
	cd /home/taport/xrfoauth/xrfserver/src/build/api-server && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT api-server/CMakeFiles/XRF_API.dir/model/ProblemDetails.cpp.o -MF CMakeFiles/XRF_API.dir/model/ProblemDetails.cpp.o.d -o CMakeFiles/XRF_API.dir/model/ProblemDetails.cpp.o -c /home/taport/xrfoauth/xrfserver/src/api-server/model/ProblemDetails.cpp

api-server/CMakeFiles/XRF_API.dir/model/ProblemDetails.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/XRF_API.dir/model/ProblemDetails.cpp.i"
	cd /home/taport/xrfoauth/xrfserver/src/build/api-server && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/taport/xrfoauth/xrfserver/src/api-server/model/ProblemDetails.cpp > CMakeFiles/XRF_API.dir/model/ProblemDetails.cpp.i

api-server/CMakeFiles/XRF_API.dir/model/ProblemDetails.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/XRF_API.dir/model/ProblemDetails.cpp.s"
	cd /home/taport/xrfoauth/xrfserver/src/build/api-server && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/taport/xrfoauth/xrfserver/src/api-server/model/ProblemDetails.cpp -o CMakeFiles/XRF_API.dir/model/ProblemDetails.cpp.s

api-server/CMakeFiles/XRF_API.dir/xrf-api-server.cpp.o: api-server/CMakeFiles/XRF_API.dir/flags.make
api-server/CMakeFiles/XRF_API.dir/xrf-api-server.cpp.o: ../api-server/xrf-api-server.cpp
api-server/CMakeFiles/XRF_API.dir/xrf-api-server.cpp.o: api-server/CMakeFiles/XRF_API.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/taport/xrfoauth/xrfserver/src/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_13) "Building CXX object api-server/CMakeFiles/XRF_API.dir/xrf-api-server.cpp.o"
	cd /home/taport/xrfoauth/xrfserver/src/build/api-server && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT api-server/CMakeFiles/XRF_API.dir/xrf-api-server.cpp.o -MF CMakeFiles/XRF_API.dir/xrf-api-server.cpp.o.d -o CMakeFiles/XRF_API.dir/xrf-api-server.cpp.o -c /home/taport/xrfoauth/xrfserver/src/api-server/xrf-api-server.cpp

api-server/CMakeFiles/XRF_API.dir/xrf-api-server.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/XRF_API.dir/xrf-api-server.cpp.i"
	cd /home/taport/xrfoauth/xrfserver/src/build/api-server && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/taport/xrfoauth/xrfserver/src/api-server/xrf-api-server.cpp > CMakeFiles/XRF_API.dir/xrf-api-server.cpp.i

api-server/CMakeFiles/XRF_API.dir/xrf-api-server.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/XRF_API.dir/xrf-api-server.cpp.s"
	cd /home/taport/xrfoauth/xrfserver/src/build/api-server && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/taport/xrfoauth/xrfserver/src/api-server/xrf-api-server.cpp -o CMakeFiles/XRF_API.dir/xrf-api-server.cpp.s

# Object files for target XRF_API
XRF_API_OBJECTS = \
"CMakeFiles/XRF_API.dir/api/AccessTokenRequestApi.cpp.o" \
"CMakeFiles/XRF_API.dir/api/InitialAuthenticationRequestApi.cpp.o" \
"CMakeFiles/XRF_API.dir/impl/AccessTokenRequestApiImpl.cpp.o" \
"CMakeFiles/XRF_API.dir/impl/InitialAuthenticationRequestApiImpl.cpp.o" \
"CMakeFiles/XRF_API.dir/model/AccessTokenClaims.cpp.o" \
"CMakeFiles/XRF_API.dir/model/AccessTokenErr.cpp.o" \
"CMakeFiles/XRF_API.dir/model/AccessTokenRsp.cpp.o" \
"CMakeFiles/XRF_API.dir/model/Helpers.cpp.o" \
"CMakeFiles/XRF_API.dir/model/InitAuthErr.cpp.o" \
"CMakeFiles/XRF_API.dir/model/InitAuthReq.cpp.o" \
"CMakeFiles/XRF_API.dir/model/InitAuthRsp.cpp.o" \
"CMakeFiles/XRF_API.dir/model/ProblemDetails.cpp.o" \
"CMakeFiles/XRF_API.dir/xrf-api-server.cpp.o"

# External object files for target XRF_API
XRF_API_EXTERNAL_OBJECTS =

api-server/libXRF_API.a: api-server/CMakeFiles/XRF_API.dir/api/AccessTokenRequestApi.cpp.o
api-server/libXRF_API.a: api-server/CMakeFiles/XRF_API.dir/api/InitialAuthenticationRequestApi.cpp.o
api-server/libXRF_API.a: api-server/CMakeFiles/XRF_API.dir/impl/AccessTokenRequestApiImpl.cpp.o
api-server/libXRF_API.a: api-server/CMakeFiles/XRF_API.dir/impl/InitialAuthenticationRequestApiImpl.cpp.o
api-server/libXRF_API.a: api-server/CMakeFiles/XRF_API.dir/model/AccessTokenClaims.cpp.o
api-server/libXRF_API.a: api-server/CMakeFiles/XRF_API.dir/model/AccessTokenErr.cpp.o
api-server/libXRF_API.a: api-server/CMakeFiles/XRF_API.dir/model/AccessTokenRsp.cpp.o
api-server/libXRF_API.a: api-server/CMakeFiles/XRF_API.dir/model/Helpers.cpp.o
api-server/libXRF_API.a: api-server/CMakeFiles/XRF_API.dir/model/InitAuthErr.cpp.o
api-server/libXRF_API.a: api-server/CMakeFiles/XRF_API.dir/model/InitAuthReq.cpp.o
api-server/libXRF_API.a: api-server/CMakeFiles/XRF_API.dir/model/InitAuthRsp.cpp.o
api-server/libXRF_API.a: api-server/CMakeFiles/XRF_API.dir/model/ProblemDetails.cpp.o
api-server/libXRF_API.a: api-server/CMakeFiles/XRF_API.dir/xrf-api-server.cpp.o
api-server/libXRF_API.a: api-server/CMakeFiles/XRF_API.dir/build.make
api-server/libXRF_API.a: api-server/CMakeFiles/XRF_API.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/taport/xrfoauth/xrfserver/src/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_14) "Linking CXX static library libXRF_API.a"
	cd /home/taport/xrfoauth/xrfserver/src/build/api-server && $(CMAKE_COMMAND) -P CMakeFiles/XRF_API.dir/cmake_clean_target.cmake
	cd /home/taport/xrfoauth/xrfserver/src/build/api-server && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/XRF_API.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
api-server/CMakeFiles/XRF_API.dir/build: api-server/libXRF_API.a
.PHONY : api-server/CMakeFiles/XRF_API.dir/build

api-server/CMakeFiles/XRF_API.dir/clean:
	cd /home/taport/xrfoauth/xrfserver/src/build/api-server && $(CMAKE_COMMAND) -P CMakeFiles/XRF_API.dir/cmake_clean.cmake
.PHONY : api-server/CMakeFiles/XRF_API.dir/clean

api-server/CMakeFiles/XRF_API.dir/depend:
	cd /home/taport/xrfoauth/xrfserver/src/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/taport/xrfoauth/xrfserver/src /home/taport/xrfoauth/xrfserver/src/api-server /home/taport/xrfoauth/xrfserver/src/build /home/taport/xrfoauth/xrfserver/src/build/api-server /home/taport/xrfoauth/xrfserver/src/build/api-server/CMakeFiles/XRF_API.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : api-server/CMakeFiles/XRF_API.dir/depend

