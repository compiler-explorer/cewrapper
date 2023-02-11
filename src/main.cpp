#include "../include/access.hpp"
#include "../include/appcontainer.hpp"
#include "../include/checks.hpp"
#include "../include/config.hpp"

#include <Windows.h>
#include <aclapi.h>

#pragma comment(lib, "Userenv.lib")

#include <filesystem>
#include <iostream>
#include <string>

namespace fs = std::filesystem;


int wmain(int argc, wchar_t *argv[])
{
    if (argc < 2)
    {
        std::wcerr << L"Too few arguments\n";
        std::wcerr << L"Usage: cewrapper.exe [-v] [--time_limit=1] ExePath [args]\n";
        return -1;
    }

    try
    {
        cewrapper::Config::get().initFromArguments(argc, argv);
    }
    catch (std::exception &e)
    {
        if (cewrapper::Config::get().debugging)
            std::cerr << e.what() << "\n";
        std::wcerr << L"Invalid arguments\n";
        return 1;
    }

    cewrapper::AppContainer container(cewrapper::Config::get());

    STARTUPINFOEX si = {};
    {
        si.StartupInfo.cb = sizeof(STARTUPINFOEX);
        SIZE_T attr_size = 0;
        InitializeProcThreadAttributeList(nullptr, 1, 0, &attr_size);
        si.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST) new BYTE[attr_size]();
        cewrapper::CheckWin32(InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attr_size),
                              L"InitializeProcThreadAttributeList");
        cewrapper::CheckWin32(UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                                                        container.getSecurityCapabilitiesPtr(),
                                                        sizeof(SECURITY_CAPABILITIES), nullptr, nullptr),
                              L"UpdateProcThreadAttribute");
    }

    // access to its own directory
    {
        auto dir = fs::path(cewrapper::Config::get().progid).parent_path().wstring();
        if (cewrapper::Config::get().debugging)
            std::wcout << "granting access to: " << dir << "\n";
        cewrapper::grant_access_to_path(container.getSid(), dir.data(), GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE);
    }

    for (auto &allowed : cewrapper::Config::get().allowed_dirs)
    {
        if (cewrapper::Config::get().debugging)
            std::wcout << "granting access to: " << allowed.path << "\n";
        cewrapper::grant_access_to_path(container.getSid(), allowed.path.data(), allowed.rights);
    }

    for (auto &allowed : cewrapper::Config::get().allowed_registry)
    {
        if (cewrapper::Config::get().debugging)
            std::wcout << "granting access to registry: " << allowed.path << ", r" << allowed.rights << "\n";
        cewrapper::grant_access_to_registry(container.getSid(), allowed.path.data(), allowed.rights, allowed.type);
    }

    std::wstring cmdline = L"\"" + std::wstring(cewrapper::Config::get().progid.c_str()) + L"\"";
    for (const auto &arg : cewrapper::Config::get().args)
        cmdline += L" " + arg;

    PROCESS_INFORMATION pi = {};
    cewrapper::CheckWin32(CreateProcessW(cewrapper::Config::get().progid.c_str(), cmdline.data(), nullptr, nullptr,
                                         false, EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr, &si.StartupInfo, &pi),
                          L"CreateProcessW");

    const int maxtime = cewrapper::Config::get().time_limit_ms;
    const int timeout = cewrapper::Config::get().loopwait_ms;
    DWORD res = 0;

    int timespent = 0;
    while (maxtime == 0 || timespent < maxtime)
    {
        timespent += timeout;
        res = WaitForSingleObject(pi.hProcess, timeout);
        if (res != WAIT_TIMEOUT)
        {
            break;
        }
    }

    if (maxtime > 0 && timespent >= maxtime)
    {
        if (res != WAIT_OBJECT_0)
        {
            const int forced_exit_status_code = 1;
            cewrapper::CheckWin32(TerminateProcess(pi.hProcess, forced_exit_status_code), L"TerminateProcess");
        }

        std::wcerr << "Maximum time elapsed\n";
    }
    else if (cewrapper::Config::get().debugging && res != WAIT_OBJECT_0)
    {
        cewrapper::OutputErrorMessage(res, L"WaitForSingleObject");
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}
