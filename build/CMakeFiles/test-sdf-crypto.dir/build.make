# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.12

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
CMAKE_SOURCE_DIR = /home/webank/fisco/sdf-crypto-cplus

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/webank/fisco/sdf-crypto-cplus/build

# Include any dependencies generated for this target.
include CMakeFiles/test-sdf-crypto.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/test-sdf-crypto.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/test-sdf-crypto.dir/flags.make

CMakeFiles/test-sdf-crypto.dir/TestSDF.cpp.o: CMakeFiles/test-sdf-crypto.dir/flags.make
CMakeFiles/test-sdf-crypto.dir/TestSDF.cpp.o: ../TestSDF.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/webank/fisco/sdf-crypto-cplus/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/test-sdf-crypto.dir/TestSDF.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/test-sdf-crypto.dir/TestSDF.cpp.o -c /home/webank/fisco/sdf-crypto-cplus/TestSDF.cpp

CMakeFiles/test-sdf-crypto.dir/TestSDF.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/test-sdf-crypto.dir/TestSDF.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/webank/fisco/sdf-crypto-cplus/TestSDF.cpp > CMakeFiles/test-sdf-crypto.dir/TestSDF.cpp.i

CMakeFiles/test-sdf-crypto.dir/TestSDF.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/test-sdf-crypto.dir/TestSDF.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/webank/fisco/sdf-crypto-cplus/TestSDF.cpp -o CMakeFiles/test-sdf-crypto.dir/TestSDF.cpp.s

# Object files for target test-sdf-crypto
test__sdf__crypto_OBJECTS = \
"CMakeFiles/test-sdf-crypto.dir/TestSDF.cpp.o"

# External object files for target test-sdf-crypto
test__sdf__crypto_EXTERNAL_OBJECTS =

test-sdf-crypto: CMakeFiles/test-sdf-crypto.dir/TestSDF.cpp.o
test-sdf-crypto: CMakeFiles/test-sdf-crypto.dir/build.make
test-sdf-crypto: libsdf-crypto_arm.so
test-sdf-crypto: CMakeFiles/test-sdf-crypto.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/webank/fisco/sdf-crypto-cplus/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable test-sdf-crypto"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/test-sdf-crypto.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/test-sdf-crypto.dir/build: test-sdf-crypto

.PHONY : CMakeFiles/test-sdf-crypto.dir/build

CMakeFiles/test-sdf-crypto.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/test-sdf-crypto.dir/cmake_clean.cmake
.PHONY : CMakeFiles/test-sdf-crypto.dir/clean

CMakeFiles/test-sdf-crypto.dir/depend:
	cd /home/webank/fisco/sdf-crypto-cplus/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/webank/fisco/sdf-crypto-cplus /home/webank/fisco/sdf-crypto-cplus /home/webank/fisco/sdf-crypto-cplus/build /home/webank/fisco/sdf-crypto-cplus/build /home/webank/fisco/sdf-crypto-cplus/build/CMakeFiles/test-sdf-crypto.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/test-sdf-crypto.dir/depend

