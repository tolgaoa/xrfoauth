# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.22

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
CMAKE_COMMAND = /usr/local/lib/python3.6/dist-packages/cmake/data/bin/cmake

# The command to remove a file.
RM = /usr/local/lib/python3.6/dist-packages/cmake/data/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/tahome/Documents/xrfoauth/src

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/tahome/Documents/xrfoauth/src/build

# Include any dependencies generated for this target.
include xrfapp/CMakeFiles/XRF.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include xrfapp/CMakeFiles/XRF.dir/compiler_depend.make

# Include the progress variables for this target.
include xrfapp/CMakeFiles/XRF.dir/progress.make

# Include the compile flags for this target's objects.
include xrfapp/CMakeFiles/XRF.dir/flags.make

xrfapp/CMakeFiles/XRF.dir/xrf_jwt.cpp.o: xrfapp/CMakeFiles/XRF.dir/flags.make
xrfapp/CMakeFiles/XRF.dir/xrf_jwt.cpp.o: ../xrfapp/xrf_jwt.cpp
xrfapp/CMakeFiles/XRF.dir/xrf_jwt.cpp.o: xrfapp/CMakeFiles/XRF.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/tahome/Documents/xrfoauth/src/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object xrfapp/CMakeFiles/XRF.dir/xrf_jwt.cpp.o"
	cd /home/tahome/Documents/xrfoauth/src/build/xrfapp && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT xrfapp/CMakeFiles/XRF.dir/xrf_jwt.cpp.o -MF CMakeFiles/XRF.dir/xrf_jwt.cpp.o.d -o CMakeFiles/XRF.dir/xrf_jwt.cpp.o -c /home/tahome/Documents/xrfoauth/src/xrfapp/xrf_jwt.cpp

xrfapp/CMakeFiles/XRF.dir/xrf_jwt.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/XRF.dir/xrf_jwt.cpp.i"
	cd /home/tahome/Documents/xrfoauth/src/build/xrfapp && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/tahome/Documents/xrfoauth/src/xrfapp/xrf_jwt.cpp > CMakeFiles/XRF.dir/xrf_jwt.cpp.i

xrfapp/CMakeFiles/XRF.dir/xrf_jwt.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/XRF.dir/xrf_jwt.cpp.s"
	cd /home/tahome/Documents/xrfoauth/src/build/xrfapp && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/tahome/Documents/xrfoauth/src/xrfapp/xrf_jwt.cpp -o CMakeFiles/XRF.dir/xrf_jwt.cpp.s

# Object files for target XRF
XRF_OBJECTS = \
"CMakeFiles/XRF.dir/xrf_jwt.cpp.o"

# External object files for target XRF
XRF_EXTERNAL_OBJECTS =

xrfapp/libXRF.a: xrfapp/CMakeFiles/XRF.dir/xrf_jwt.cpp.o
xrfapp/libXRF.a: xrfapp/CMakeFiles/XRF.dir/build.make
xrfapp/libXRF.a: xrfapp/CMakeFiles/XRF.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/tahome/Documents/xrfoauth/src/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX static library libXRF.a"
	cd /home/tahome/Documents/xrfoauth/src/build/xrfapp && $(CMAKE_COMMAND) -P CMakeFiles/XRF.dir/cmake_clean_target.cmake
	cd /home/tahome/Documents/xrfoauth/src/build/xrfapp && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/XRF.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
xrfapp/CMakeFiles/XRF.dir/build: xrfapp/libXRF.a
.PHONY : xrfapp/CMakeFiles/XRF.dir/build

xrfapp/CMakeFiles/XRF.dir/clean:
	cd /home/tahome/Documents/xrfoauth/src/build/xrfapp && $(CMAKE_COMMAND) -P CMakeFiles/XRF.dir/cmake_clean.cmake
.PHONY : xrfapp/CMakeFiles/XRF.dir/clean

xrfapp/CMakeFiles/XRF.dir/depend:
	cd /home/tahome/Documents/xrfoauth/src/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/tahome/Documents/xrfoauth/src /home/tahome/Documents/xrfoauth/src/xrfapp /home/tahome/Documents/xrfoauth/src/build /home/tahome/Documents/xrfoauth/src/build/xrfapp /home/tahome/Documents/xrfoauth/src/build/xrfapp/CMakeFiles/XRF.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : xrfapp/CMakeFiles/XRF.dir/depend

