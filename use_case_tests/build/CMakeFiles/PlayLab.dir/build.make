# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

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
CMAKE_COMMAND = /usr/local/bin/cmake

# The command to remove a file.
RM = /usr/local/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/kanka/Desktop/HEPlayLab/use_case_tests

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/kanka/Desktop/HEPlayLab/use_case_tests/build

# Include any dependencies generated for this target.
include CMakeFiles/PlayLab.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/PlayLab.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/PlayLab.dir/flags.make

CMakeFiles/PlayLab.dir/playlab.cpp.o: CMakeFiles/PlayLab.dir/flags.make
CMakeFiles/PlayLab.dir/playlab.cpp.o: ../playlab.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/kanka/Desktop/HEPlayLab/use_case_tests/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/PlayLab.dir/playlab.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/PlayLab.dir/playlab.cpp.o -c /home/kanka/Desktop/HEPlayLab/use_case_tests/playlab.cpp

CMakeFiles/PlayLab.dir/playlab.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/PlayLab.dir/playlab.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/kanka/Desktop/HEPlayLab/use_case_tests/playlab.cpp > CMakeFiles/PlayLab.dir/playlab.cpp.i

CMakeFiles/PlayLab.dir/playlab.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/PlayLab.dir/playlab.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/kanka/Desktop/HEPlayLab/use_case_tests/playlab.cpp -o CMakeFiles/PlayLab.dir/playlab.cpp.s

# Object files for target PlayLab
PlayLab_OBJECTS = \
"CMakeFiles/PlayLab.dir/playlab.cpp.o"

# External object files for target PlayLab
PlayLab_EXTERNAL_OBJECTS =

../PlayLab: CMakeFiles/PlayLab.dir/playlab.cpp.o
../PlayLab: CMakeFiles/PlayLab.dir/build.make
../PlayLab: /home/kanka/Desktop/SEAL/native/lib/libseal-3.4.a
../PlayLab: CMakeFiles/PlayLab.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/kanka/Desktop/HEPlayLab/use_case_tests/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable ../PlayLab"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/PlayLab.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/PlayLab.dir/build: ../PlayLab

.PHONY : CMakeFiles/PlayLab.dir/build

CMakeFiles/PlayLab.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/PlayLab.dir/cmake_clean.cmake
.PHONY : CMakeFiles/PlayLab.dir/clean

CMakeFiles/PlayLab.dir/depend:
	cd /home/kanka/Desktop/HEPlayLab/use_case_tests/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/kanka/Desktop/HEPlayLab/use_case_tests /home/kanka/Desktop/HEPlayLab/use_case_tests /home/kanka/Desktop/HEPlayLab/use_case_tests/build /home/kanka/Desktop/HEPlayLab/use_case_tests/build /home/kanka/Desktop/HEPlayLab/use_case_tests/build/CMakeFiles/PlayLab.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/PlayLab.dir/depend
