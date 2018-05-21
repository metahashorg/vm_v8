# libv8js_example
Repository provides examples of how to solve some tasks in C++ using v8 library.

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
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:src/v8/lib
```

## Features
1. Output of the bytecode which corresponds to the code compiled from js file:
```shell
./vm_v8 -mode 0 [path to the file containing js-code]
```
> Program redirects the output of ignition compiler to the console.

2. Counting the number of bytecode instructions for each type of the bytecode.
```shell
./vm_v8 -mode 1 [path to the file containing js-code]
```

3. Gaining information about the amount of memory allocated during running the script. Two indicators are displayed: heap size and amount of allocated memory.
```shell
./vm_v8 -mode 2 [path to the file containing js-code]
```

4. Initialization of contract directly in the process memory.
```shell
(under development)
```

5. Reading contract's status directly from the memory.
```shell
(under development)
```

6. Testing the work with external variable and function.
```shell
./vm_v8 -mode 5 [int32]
```
> Program shows the entered value stored in the native variable using the native function.

7. Generating SHA-256 hash for a string (js-function: meta_sha256).
```shell
./vm_v8 -mode 6 [string]
```

8. Verifying ECDSA signature (js-function: meta_MHC_check_sign).
```shell
 ./vm_v8 -mode 7
 ```
> There is no input data. Values are checked by default.

9. Generating address on the public key.
```shell
./vm_v8 -mode 8 [public key in the form of hex string]
```


10. Generating cache of the compiled code.
```shell
./vm_v8 -mode 9 [address] [path to the file containing js-code]
```
> There will be 3 files created:
>```shell
>       1. [address].dbg  #  debug info.
>       2. [address].bt  #  bytecode listing output.
>       3. [address].cmpl  #  compiler cache.
>```
