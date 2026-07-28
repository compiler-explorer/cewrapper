# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`cewrapper.exe` is a Windows-only jailing wrapper used by Compiler Explorer to run untrusted executables (compilers, user programs) under an AppContainer sandbox plus a Job object with resource limits. It is a single-binary MSVC C++ project — no CMake, no package manager, no test suite.

```
cewrapper.exe [-v|-vv] [--summary] [--config=C:\path\config.json] [--home=C:\cwd]
              [--time_limit=<seconds>] [--suspend] [--wait] C:\full\path\to\exe.exe [args...]
cewrapper.exe --prepare-nul
```

`--prepare-nul` is a standalone maintenance mode (no target exe): it grants the app package SIDs access
to `\Device\Null` and exits. It must run elevated, once per boot — the kernel resets that DACL at boot
and the default locks AppContainers out of `NUL`. `infra/init/start.ps1` calls it via `PrepareNulDevice`.

Note the `--time_limit=` value is in **seconds** and is multiplied by 1000 into `time_limit_ms`.

## Build

MSVC only, x64 only, `Debug|x64` and `Release|x64` configurations, toolset v142, `/std:c++latest`, warning level 4.

```
msbuild cewrapper.vcxproj -t:rebuild -property:Configuration=Release -property:Platform=x64
```

Output lands in `x64\Release\cewrapper.exe`. CI (`.github/workflows/build-test.yml`) runs exactly this on `windows-2022` and publishes the exe as a release artifact on tags. Despite the workflow name there are **no tests** — verification is building plus running the exe manually against a real target program on Windows.

The repo may be checked out on Linux (e.g. inside the Compiler Explorer tree), where nothing compiles: every source file pulls in `windows.h`, `userenv.h`, `aclapi.h`, `winsafer.h`, `ntsecapi.h`. Code changes made there can only be reviewed by reading, not built.

Formatting: clang-format with the checked-in `.clang-format` (Allman braces, 4 spaces, 120 cols, `AccessModifierOffset: 0` so `private:`/`public:` sit at member indent).

Adding a source file means editing `cewrapper.vcxproj` (`ClCompile`/`ClInclude` item groups) and ideally `cewrapper.vcxproj.filters`.

## Architecture

`wmain` (`src/main.cpp`) parses config, constructs one `Job`, then dispatches to one of two sandboxing strategies:

- `execute_using_appcontainer` — the default (`use_appcontainer: true`). Creates an `AppContainer`, builds a `STARTUPINFOEX` carrying `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`, grants the container SID ACLs on the home dir and each configured path/registry key, spawns, then revokes the path ACLs afterwards.
- `execute_using_lower_rights` — fallback when `use_appcontainer` is false. Uses the Safer API (`SaferCreateLevel` / `SaferComputeTokenFromLevel` at `SAFER_LEVELID_NORMALUSER`) and `CreateProcessAsUserW`.

Both funnel into `SpawnProcess`, which is the only place a process is created. Invariant: the child is **always** created `CREATE_SUSPENDED`, assigned to the job with `job.AddProcess` while still suspended, and only then resumed (unless `--suspend`). Don't reorder that — a process that starts before it is in the job escapes the limits. `SpawnProcess` also sets `lpDesktop` to `winsta0\default`; without it AppContainer children can die with `0xc0000142` (STATUS_DLL_INIT_FAILED).

Module responsibilities:

- `config.{hpp,cpp}` — `Config` is a **process-global singleton** (`Config::get()`, backed by a file-scope `_main_config`). CLI flags are parsed in order until the first non-flag argument, which becomes `progid`; everything after is `args`. `--config=` loads the JSON via the vendored `3rdparty/nlohmann/json.hpp`. `Job` and `AppContainer` each take `const Config` **by value**, so config mutated after their construction won't be seen by them.
- `appcontainer.{hpp,cpp}` — profile is named `cesandbox<pid>`, created in the constructor and deleted in the destructor. `InitializeCapabilities()` builds the `SID_AND_ATTRIBUTES` vector; `sec_cap.CapabilityCount` is derived from `capabilities.size()`, so capabilities can be added/removed by editing only that function. The `capabilities` vector is the backing store for `sec_cap.Capabilities` and must outlive any use of `sec_cap`. `DeriveCapabilitySidsFromName` is resolved dynamically from `KernelBase.dll` (not in an import lib).
- `job.{hpp,cpp}` — job named `cejob<pid>`, always sets `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`; process/time/memory limits are only applied when the corresponding config value is > 0. Destructor terminates the job, prints the `--summary`/`-vv` stats, then closes the handle.
- `access.{hpp,cpp}` — read-modify-write of DACLs via `GetNamedSecurityInfoW` / `SetEntriesInAclW` / `SetNamedSecurityInfoW`, for `SE_FILE_OBJECT` and the three registry views. `grant_access_to_nul_device` is the exception: `NUL` is a device object, not a file object, so it goes through `CreateFileW(L"\\\\.\\NUL", READ_CONTROL | WRITE_DAC, …)` plus `GetKernelObjectSecurity` / `SetKernelObjectSecurity`. Don't try to reach it with `SE_FILE_OBJECT` — that was tried in `28751a1`..`5786c0a` and does not work.
- `checks.{hpp,cpp}` — error funnel. `CheckWin32`/`CheckStatus` print via `FormatMessageW` and `throw std::exception`, caught in `wmain`; `CheckStatusAllowFail` only warns. AppContainer creation failures call `abort()` instead of throwing.
- `exitcodes.hpp` — `SpecialExitCode` values collide with real child exit codes by design-so-far (see the `todo` in that file); the wrapper returns the child's exit code on the normal path.

## Config JSON

```json
{
  "use_appcontainer": true,
  "mem_max": 0,
  "pids_max": 0,
  "allowed_paths":    [{ "path": "C:\\some\\dir", "rw": false, "noexec": false }],
  "allowed_registry": [{ "path": "MACHINE\\Software\\...", "rw": false, "type": "normal" }]
}
```

Paths get `GENERIC_READ`, plus `GENERIC_WRITE` if `rw`, plus `GENERIC_EXECUTE` unless `noexec`. Registry keys get `GENERIC_READ`, or `GENERIC_ALL` if `rw`; `type` is `normal` | `wow6464` | `wow6432`. `allowed_paths` and `allowed_registry` are indexed unconditionally (`data["allowed_paths"]`), so both keys must be present.

## Known landmines

- `Config::loadFromFile` selects the registry type with `jsregtype.compare("wow6464")` used as a boolean. `std::string::compare` returns 0 on equality, so those branches are inverted — every type other than `wow6464` currently resolves to `wow6464`. Fix carefully if you touch it; existing configs may depend on the current behaviour.
- Path ACLs granted to the container SID are revoked at the end of `execute_using_appcontainer`, but registry grants are never revoked.
- If the process crashes and a later run reuses the same PID, `CreateAppContainerProfile` returns `ERROR_ALREADY_EXISTS`; the code deletes and recreates the profile in that case.
