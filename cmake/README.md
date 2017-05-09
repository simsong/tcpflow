CMake for TcpFlow
=================


Objective
---------

The provided CMake scripts within the **TcpFlow** source code are not a replacement for autotools/automake scripts.

The autotools/automake scripts are required to generate the header `config.h` and also to build official release.

But CMake provide other advantages:

* Generate IDE project settings as for Qt Creator, Eclipse CDT or Visual C++.
* Generate `ninja` build scripts as an alternative to `Makefiles`.
* Provide build type *Coverage* and targets to visualize reports.
* Facilities for static and runtime source code analysis.
* ...

The following chapters explain how to use the features available by the current CMake scripts.


Quick start
-----------

Clone Git repository and its submodules recursively.

    git clone --recursive https://github.com/simsong/tcpflow
    cd tcpflow

Generate the header `config.h` (autotools check the availability of libraries and features within your environment).

    ./boostrap.sh
    ./configure

And use CMake.

    mkdir build-dir
    cd    build-dir
    cmake ..                   # Generate the build scripts (e.g. Makefiles)
    cd    ..
    cmake --build build-dir    # Run the build tool (e.g. make)


CMake v3.1
----------

The CMake scripts require CMake v3.1 (2015) that may not be available on your platform. To get a recent CMake version, you may build it from source code:

    git clone https://cmake.org/cmake.git
    cd cmake
    git checkout v3.4.3
    cmake .
    cmake --build .

To install freshly built CMake:

    cmake install   # To be checked

Or you may use `checkinstall` to create a package `*.deb`

    sudo apt install checkinstall
    sudo checkinstall


Build Directory
---------------

Tools like autotools usually write temporary files within the source code tree. CMake can also pollute the source code tree with temporaries, but you can decide where CMake write its temporary files, libraries and executables.

The classic way is to create a directory `build`:

    cd /path/to/tcpflow/root/dir
    mkdir build
    ( cd  build && cmake .. )
    cmake --build build

But you can also decide any other directory name:

    cd /path/to/tcpflow/root/dir
    mkdir /my/build/directory
    ( cd  /my/build/directory && cmake $OLDPWD )
    cmake --build /my/build/directory


Build Tool
----------

CMake does not build the project: CMake is not a build tool. CMake generates files for a build tool as [gmake, nmake, ninja, Visual Studio...](https://cmake.org/cmake/help/latest/manual/cmake-generators.7.html).

### Makefiles

On most Unix-like platforms, CMake generates *Unix Makefiles* when GNU Make is available. Therefore, command `make` can also be used to build the project.

    mkdir build
    cd    build
    cmake ..     # Generate Makefiles
    make -j4     # Build using four jobs

To enable verbose mode use `VERBOSE=1` to display the full command lines during build.

    make -j4 VERBOSE=1

### Ninja

If [`ninja`](https://github.com/ninja-build/ninja) is available, you can use it instead of `make`.

    mkdir build
    cd    build
    cmake .. -G Ninja
    ninja

Use argument `-v` for verbose mode:

    mkdir build
    cd    build
    cmake .. -G Ninja
    ninja -v

### CMake argument `--build <build-dir>`

Use `cmake --build <build-dir>` to abstract the build tool.

    mkdir build
    cd    build
    cmake .. -G "${MY_CMAKE_GENERATOR}"
    cmake --build .

### Integrated Development Environment

Qt Creator is natively compatible with CMake and the root file `CMakeLists.txt` can be opened directly from Qt Creator. For other IDE, you can use CMake argument `-G`. Below example is for IDE Eclipse using `make`:

    mkdir build
    cd    build
    cmake .. -G "Eclipse CDT4 - Unix Makefiles"

Please see [IDE Build Tool Generators](https://cmake.org/cmake/help/latest/manual/cmake-generators.7.html#ide-build-tool-generators) in CMake documentation.


Compiler
--------

You can also select another compiler using `CC` and `CXX` environment variables.

    mkdir build
    cd    build
    CC=clang CXX=clang++ cmake ..
    cmake --build .

    mkdir build
    cd    build
    CC=clang
    CXX=clang++
    cmake ..
    cmake --build .


Build Types
-----------

The CMake scripts of **TcpFlow** project supports three build types: **Debug**, **Release** and **Coverage**. You can select the build type with the variable **`CMAKE_BUILD_TYPE`**. The default build type is **Debug**.

* **Debug** (use options `-O0` and `-g3` for GCC and Clang compilers)

        mkdir build-debug
        cd    build-debug
        cmake .. -DCMAKE_BUILD_TYPE=Debug

* **Release** (still include debug info `-g3` for GCC and Clang compilers)

        mkdir build-release
        cd    build-release
        cmake .. -DCMAKE_BUILD_TYPE=Release

* **Coverage** (GCC only)

        mkdir build-coverage
        cd    build-coverage
        cmake .. -DCMAKE_BUILD_TYPE=Coverage


Target
------

Instead of building `all` just build a library and its dependencies.

    make netvix


Compiler/Linker cache `ccache`
------------------------------

The command `ccache` can speed up compilation and link. If you clean and rebuild often, you may consider installing `ccache`. The CMake scripts of **TcpFlow** project use `ccache` when available.

    sudo apt install ccache
    
    cd build
    cmake ..
    time make  # First build: ccache caches all compiler output
    
    make clean
    time make  # ccache detects same input and bypasses the compiler

In the same way, the CMake scripts detect presence on command `distcc`.


Options
-------

### Static code analysis

CMake script of **TcpFlow** project enables the option `CMAKE_EXPORT_COMPILE_COMMANDS` that produce the file `compile_commands.json` during the build. This file can be then used by static code analysis tools as `clang-check`:

    awk -F: '/"file"/{print $2 }' build/compile_commands.json | xargs clang-check -fixit -p build

### Run-time code analysis

Option `SANITIZE=ON` let you run the run-time code analysis.

    cmake .. -DSANITIZE=ON

### Optimizations

Option `MARCH` let you control the `CFLAG -march`. In order to use recent processor instructions set, the CMake script uses default option `MARCH=corei7` (`-march=corei7`). You can use `MARCH=native` to request `gcc` to provide the real *cpu-type* used in order to keep a reproducible build on another machine. You can use empty option `MARCH=` to unset flag `-march`.

    cmake .. -DMARCH=native  # Detect corresponding cpu-type before build
    cmake .. -DMARCH=        # Disable flag -march

Option `OPTIM` let you control the flags `-O0 -Og -O1 -Os -O2 -O3 -Ofast`.

    cmake .. -DOPTIM=-Ofast

The default value `OPTIM` depends on the value `CMAKE_BUILD_TYPE`:

* Release: Empty `OPTIM` => Use the default `-O2` set by CMake
* Debug: Use `-O0` because `-Og` does not always step-by-step debugging
* Coverage: Use `-O0` to ensure code line/branch coverage


Test
----

Use `cmake --build .` and `ctest` as an abstraction of the specific build tool (`ninja` or `make`)

    cmake .. -DCMAKE_BUILD_TYPE=Release -G Ninja
    cmake --build .
    ctest

    cmake .. -DCMAKE_BUILD_TYPE=Release -G Ninja
    cmake --build . --target netvix
