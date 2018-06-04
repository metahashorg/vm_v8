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
1. Output of the bytecode:
```shell
./vm_v8 -mode bt -js [js file path]
```
> Program redirects the output of ignition compiler to the console.

2. Counting the number of instructions: 
```shell
./vm_v8 -mode btcount -js [js file path]
```

3. Memory footprint:
```shell
./vm_v8 -mode mem -js [js file path]
```

4. Testing external variable:
```shell
./vm_v8 -mode external -intarg [integer]
```

5. sha256:
```shell
./vm_v8 -mode sha256 -strarg [string]
```

6. Signature check:
```shell
./vm_v8 -mode sig
```

7. Generating address on public key:
```shell
./vm_v8 -mode newaddr -strarg [public key in the form of hex string]
```

8. Compiler test:
```shell
 ./vm_v8 -mode compile -a ADDR -js FILE.JS
 ```
> There is no input data. Values are checked by default.

9. Initialization status: 
```shell
./vm_v8 -mode run -a ADDR -cmd run.js -js FILE.JS -cmpl FILE.cmpl -snap_o I_FILE.shot
```

10. Status dump:
```shell
./vm_v8 -mode run -a ADDR -cmd run.js -snap_i I_FILE.shot -snap_o I_FILE.shot
```

## Initialization and contract status dump test.

`ADDR` — address of the contract

`FILE.JS` — file containing core js code. When running contract initialization test there is a contract code (`contract.js`).

`FILE.cmpl` — file containing compiler cache, is equal to `FILE.js`.

`run.js` -  file containing js code, that conducts one of 2 operations, i.e. initialization or status dump (`init.js` and `dump.js`)

`I_FILE.shot` - input file of the virtual machine memory snapshot, it is mandatory for the status test and optional for the initialization test.

`I_FILE.shot` — file containing memory snapshot after core code and command code

Following files are added to the project:
```shell
contract.js
contract.cmpl
init.js
dump.js
```

### Command line for running initialization test:
```shell
./vm_v8 -mode run -a 0xaddress -cmd init.js -js contract.js -cmpl contract.cmpl -snap_o init.shot
```
Output:
> snapshot `init.shot
`
> Entry in the `err.log` file shows that contract has been initialized successfully:
`ContractStateTest:[object Object]`

### Running status dump test:
```shell
./test -mode run -a 0xaddress -cmd dump.js -snap_i init.shot -snap_o result.shot
```
Output:
> Final snapshot `result.shot`.

> Entry in the `err.log` file regarding contract status: 
> ```shell 
> ContractStateTest:
> { "items":
>   [
>     {
>       "key":"ammount",
>       "type":"number",
>       "value":220
>     },
>     {
>       "key":"data",
>       "type":"Map",
>       "value":
>       [
>         ["Jane",100],["Bob",120]
>       ]
>     }
>   ]
> }
> ```
