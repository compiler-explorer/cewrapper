# cewrapper

jailing wrapper for execution of windows applications

## usage

`cewrapper.exe C:\full\path\to\executable.exe arguments`

for some verboseness, use `cewrapper.exe -v C:\full\path\to\executable.exe arguments`

## host preparation

`cewrapper.exe --prepare-nul`

Grants ALL APPLICATION PACKAGES and ALL RESTRICTED APPLICATION PACKAGES read/write/execute on the NUL
device (`\Device\Null`). Without this, a sandboxed process that opens `NUL`, or redirects its stdio
there, fails with access denied.

The kernel recreates `\Device\Null` with a default security descriptor on every boot, so this has to be
run again after each boot, elevated, before any sandboxed process starts.

## dev

To format your sourcefiles, use clang-format. Can be downloaded along with llvm [here](https://github.com/llvm/llvm-project/releases/download/llvmorg-15.0.6/LLVM-15.0.6-win64.exe)
