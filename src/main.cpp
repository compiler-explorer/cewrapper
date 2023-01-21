#include "../include/checks.hpp"
#include "../include/config.hpp"
#include "../include/access.hpp"


#include <Windows.h>
#include <aclapi.h>
#include <userenv.h>
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
    catch (...)
    {
        // std::cerr << e.what() << "\n";
        std::wcerr << L"Invalid arguments\n";
        return 1;
    }

    SECURITY_CAPABILITIES sec_cap = {};
    {
        HRESULT hr = CreateAppContainerProfile(L"cesandbox", L"cesandbox", L"cesandbox", nullptr, 0, &sec_cap.AppContainerSid);
        if (HRESULT_CODE(hr) == ERROR_ALREADY_EXISTS)
        {
            if (cewrapper::Config::get().extra_debugging)
                std::wcout << "CreateAppContainerProfile - ALREADY_EXISTS, deriving from profile\n";
            hr = DeriveAppContainerSidFromAppContainerName(L"cesandbox", &sec_cap.AppContainerSid);
        }

        if (FAILED(hr))
        {
            if (cewrapper::Config::get().debugging)
                std::wcerr << "CreateAppContainerProfile or DeriveAppContainerSidFromAppContainerName - Failed with " << hr << "\n";
            abort();
        }
    }

    STARTUPINFOEX si = {};
    {
        si.StartupInfo.cb = sizeof(STARTUPINFOEX);
        SIZE_T attr_size = 0;
        InitializeProcThreadAttributeList(NULL, 1, 0, &attr_size);
        si.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST) new BYTE[attr_size]();
        cewrapper::CheckWin32(InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attr_size),
                              L"InitializeProcThreadAttributeList");
        cewrapper::CheckWin32(UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                                                        &sec_cap, sizeof(SECURITY_CAPABILITIES), nullptr, nullptr),
                              L"UpdateProcThreadAttribute");
    }

    {
        auto dir = fs::path(cewrapper::Config::get().progid).parent_path().wstring();
        cewrapper::grant_access(static_cast<wchar_t *>(sec_cap.AppContainerSid), dir.data(), GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE);
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
