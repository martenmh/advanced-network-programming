# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.10

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
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
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/marten/Documents/anp

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/marten/Documents/anp/build

# Include any dependencies generated for this target.
include CMakeFiles/anp_server.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/anp_server.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/anp_server.dir/flags.make

CMakeFiles/anp_server.dir/server-client/tcp_server.c.o: CMakeFiles/anp_server.dir/flags.make
CMakeFiles/anp_server.dir/server-client/tcp_server.c.o: ../server-client/tcp_server.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/marten/Documents/anp/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/anp_server.dir/server-client/tcp_server.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/anp_server.dir/server-client/tcp_server.c.o   -c /home/marten/Documents/anp/server-client/tcp_server.c

CMakeFiles/anp_server.dir/server-client/tcp_server.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/anp_server.dir/server-client/tcp_server.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/marten/Documents/anp/server-client/tcp_server.c > CMakeFiles/anp_server.dir/server-client/tcp_server.c.i

CMakeFiles/anp_server.dir/server-client/tcp_server.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/anp_server.dir/server-client/tcp_server.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/marten/Documents/anp/server-client/tcp_server.c -o CMakeFiles/anp_server.dir/server-client/tcp_server.c.s

CMakeFiles/anp_server.dir/server-client/tcp_server.c.o.requires:

.PHONY : CMakeFiles/anp_server.dir/server-client/tcp_server.c.o.requires

CMakeFiles/anp_server.dir/server-client/tcp_server.c.o.provides: CMakeFiles/anp_server.dir/server-client/tcp_server.c.o.requires
	$(MAKE) -f CMakeFiles/anp_server.dir/build.make CMakeFiles/anp_server.dir/server-client/tcp_server.c.o.provides.build
.PHONY : CMakeFiles/anp_server.dir/server-client/tcp_server.c.o.provides

CMakeFiles/anp_server.dir/server-client/tcp_server.c.o.provides.build: CMakeFiles/anp_server.dir/server-client/tcp_server.c.o


CMakeFiles/anp_server.dir/server-client/common.c.o: CMakeFiles/anp_server.dir/flags.make
CMakeFiles/anp_server.dir/server-client/common.c.o: ../server-client/common.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/marten/Documents/anp/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/anp_server.dir/server-client/common.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/anp_server.dir/server-client/common.c.o   -c /home/marten/Documents/anp/server-client/common.c

CMakeFiles/anp_server.dir/server-client/common.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/anp_server.dir/server-client/common.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/marten/Documents/anp/server-client/common.c > CMakeFiles/anp_server.dir/server-client/common.c.i

CMakeFiles/anp_server.dir/server-client/common.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/anp_server.dir/server-client/common.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/marten/Documents/anp/server-client/common.c -o CMakeFiles/anp_server.dir/server-client/common.c.s

CMakeFiles/anp_server.dir/server-client/common.c.o.requires:

.PHONY : CMakeFiles/anp_server.dir/server-client/common.c.o.requires

CMakeFiles/anp_server.dir/server-client/common.c.o.provides: CMakeFiles/anp_server.dir/server-client/common.c.o.requires
	$(MAKE) -f CMakeFiles/anp_server.dir/build.make CMakeFiles/anp_server.dir/server-client/common.c.o.provides.build
.PHONY : CMakeFiles/anp_server.dir/server-client/common.c.o.provides

CMakeFiles/anp_server.dir/server-client/common.c.o.provides.build: CMakeFiles/anp_server.dir/server-client/common.c.o


# Object files for target anp_server
anp_server_OBJECTS = \
"CMakeFiles/anp_server.dir/server-client/tcp_server.c.o" \
"CMakeFiles/anp_server.dir/server-client/common.c.o"

# External object files for target anp_server
anp_server_EXTERNAL_OBJECTS =

anp_server: CMakeFiles/anp_server.dir/server-client/tcp_server.c.o
anp_server: CMakeFiles/anp_server.dir/server-client/common.c.o
anp_server: CMakeFiles/anp_server.dir/build.make
anp_server: CMakeFiles/anp_server.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/marten/Documents/anp/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking C executable anp_server"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/anp_server.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/anp_server.dir/build: anp_server

.PHONY : CMakeFiles/anp_server.dir/build

CMakeFiles/anp_server.dir/requires: CMakeFiles/anp_server.dir/server-client/tcp_server.c.o.requires
CMakeFiles/anp_server.dir/requires: CMakeFiles/anp_server.dir/server-client/common.c.o.requires

.PHONY : CMakeFiles/anp_server.dir/requires

CMakeFiles/anp_server.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/anp_server.dir/cmake_clean.cmake
.PHONY : CMakeFiles/anp_server.dir/clean

CMakeFiles/anp_server.dir/depend:
	cd /home/marten/Documents/anp/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/marten/Documents/anp /home/marten/Documents/anp /home/marten/Documents/anp/build /home/marten/Documents/anp/build /home/marten/Documents/anp/build/CMakeFiles/anp_server.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/anp_server.dir/depend

