# libv8js_example
Repository provides examples of how to solve some tasks in C ++ using v8 library.

## Dependencies
The following libraries are required to be installed:
```shell
libopenssl
V8 # Completed build of V8 libraries can be find in the repository.
```

## Building from source
```shell
git clone https://github.com/metahashorg/vm_v8

cd vm_8
cd build
./build.sh
```

`/src` directory contains built vm_v8 utility.
Before launching the utility, it is needed to run the following command:
```shell
export LD_LIBRARY_PATH = $ LD_LIBRARY_PATH: src / v8 / lib
```

## Features
1. How to get ignition bytecode from the js code.
2. How to get and parse bytecode with regard to specifying the number of instructions.
3. How to initialize contract's status in the stack.
4. How to read contract's status in the stack.
5. How to get the amount of memory needed by the virtual machine.
6. How to generate SHA-256 hash of a string.
7. How to verify ECDSA signature.
8. How to get Metahash address. 
9. How to save compiled js code cache.
