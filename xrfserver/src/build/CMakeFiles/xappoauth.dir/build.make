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
CMAKE_SOURCE_DIR = /home/taport/Documents/xrfoauth/xrfserver/src

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/taport/Documents/xrfoauth/xrfserver/src/build

# Include any dependencies generated for this target.
include CMakeFiles/xappoauth.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/xappoauth.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/xappoauth.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/xappoauth.dir/flags.make

CMakeFiles/xappoauth.dir/main.cpp.o: CMakeFiles/xappoauth.dir/flags.make
CMakeFiles/xappoauth.dir/main.cpp.o: ../main.cpp
CMakeFiles/xappoauth.dir/main.cpp.o: CMakeFiles/xappoauth.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/taport/Documents/xrfoauth/xrfserver/src/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/xappoauth.dir/main.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/xappoauth.dir/main.cpp.o -MF CMakeFiles/xappoauth.dir/main.cpp.o.d -o CMakeFiles/xappoauth.dir/main.cpp.o -c /home/taport/Documents/xrfoauth/xrfserver/src/main.cpp

CMakeFiles/xappoauth.dir/main.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/xappoauth.dir/main.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/taport/Documents/xrfoauth/xrfserver/src/main.cpp > CMakeFiles/xappoauth.dir/main.cpp.i

CMakeFiles/xappoauth.dir/main.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/xappoauth.dir/main.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/taport/Documents/xrfoauth/xrfserver/src/main.cpp -o CMakeFiles/xappoauth.dir/main.cpp.s

# Object files for target xappoauth
xappoauth_OBJECTS = \
"CMakeFiles/xappoauth.dir/main.cpp.o"

# External object files for target xappoauth
xappoauth_EXTERNAL_OBJECTS =

xappoauth: CMakeFiles/xappoauth.dir/main.cpp.o
xappoauth: CMakeFiles/xappoauth.dir/build.make
xappoauth: api-server/libXRF_API.a
xappoauth: xrfapp/libXRF.a
xappoauth: /usr/lib/x86_64-linux-gnu/libssl.a
xappoauth: /usr/lib/x86_64-linux-gnu/libcrypto.a
xappoauth: /usr/local/lib/libpistache.so
xappoauth: CMakeFiles/xappoauth.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/taport/Documents/xrfoauth/xrfserver/src/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable xappoauth"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/xappoauth.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/xappoauth.dir/build: xappoauth
.PHONY : CMakeFiles/xappoauth.dir/build

CMakeFiles/xappoauth.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/xappoauth.dir/cmake_clean.cmake
.PHONY : CMakeFiles/xappoauth.dir/clean

CMakeFiles/xappoauth.dir/depend:
	cd /home/taport/Documents/xrfoauth/xrfserver/src/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/taport/Documents/xrfoauth/xrfserver/src /home/taport/Documents/xrfoauth/xrfserver/src /home/taport/Documents/xrfoauth/xrfserver/src/build /home/taport/Documents/xrfoauth/xrfserver/src/build /home/taport/Documents/xrfoauth/xrfserver/src/build/CMakeFiles/xappoauth.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/xappoauth.dir/depend

