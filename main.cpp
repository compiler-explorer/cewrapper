#include <Windows.h>
#include <aclapi.h>
#include <userenv.h>
#pragma comment(lib, "Userenv.lib")

#include <iostream>
#include <filesystem>

namespace fs = std::filesystem;

bool debug = false;

static void OutputErrorMessage(DWORD err, const wchar_t *action) {
    LPTSTR errorText = nullptr;
    DWORD len = FormatMessageW(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&errorText, 0, nullptr
    );

    if (len) {
        if (debug) {
            std::wcerr << L"ERROR: " << action << L" - " << errorText << std::endl;
        } else {
            std::wcerr << L"ERROR: " << errorText << std::endl;
        }
    } else {
        std::wcerr << L"ERROR: unknown" << std::endl;
    }
}

static void CheckWin32(BOOL res, const wchar_t *action) {
    if (res)
        return;

    OutputErrorMessage(GetLastError(), action);
    abort();
}

static void CheckStatus(DWORD status, const wchar_t *action) {
    if (status == ERROR_SUCCESS) return;

    OutputErrorMessage(status, action);
    abort();
}

int wmain (int argc, wchar_t *argv[]) {
    if (argc < 2) {
        std::wcerr << L"Too few arguments\n";
        std::wcerr << L"Usage: cewrapper.exe ExePath [args]\n";
        return -1;
    }

    int arg_idx = 1;
    if (wcscmp(argv[arg_idx], L"-v") == 0) {
        debug = true;
        arg_idx++;
    }

    std::wstring progid = argv[arg_idx];
    std::vector<std::wstring> args;
    for (; arg_idx < argc; ++arg_idx)
        args.push_back(argv[arg_idx]);

    SECURITY_CAPABILITIES sec_cap = {};
    {
        HRESULT hr = CreateAppContainerProfile(L"cesandbox", L"cesandbox", L"cesandbox", nullptr, 0, &sec_cap.AppContainerSid);
        if (HRESULT_CODE(hr) == ERROR_ALREADY_EXISTS) {
            hr = DeriveAppContainerSidFromAppContainerName(L"cesandbox", &sec_cap.AppContainerSid);
        }
        if (FAILED(hr))
            abort();
    }

    STARTUPINFOEX si = {};
    {
        si.StartupInfo.cb = sizeof(STARTUPINFOEX);
        SIZE_T attr_size = 0;
        InitializeProcThreadAttributeList(NULL, 1, 0, &attr_size);
        si.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)new BYTE[attr_size]();
        CheckWin32(InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attr_size), L"InitializeProcThreadAttributeList");
        CheckWin32(UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &sec_cap, sizeof(SECURITY_CAPABILITIES), nullptr, nullptr), L"UpdateProcThreadAttribute");
    }

    {
        auto dir = fs::path(progid).parent_path().wstring();
        EXPLICIT_ACCESSW access = {};
        {
            access.grfAccessPermissions = GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE;
            access.grfAccessMode = GRANT_ACCESS;
            access.grfInheritance = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
            access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
            access.Trustee.TrusteeType = TRUSTEE_IS_GROUP;
            access.Trustee.ptstrName = (wchar_t*)*&sec_cap.AppContainerSid;
        }

        PSECURITY_DESCRIPTOR pSecurityDescriptor = nullptr;
        ACL* prevAcl = nullptr;
        CheckStatus(GetNamedSecurityInfoW(dir.data(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, &prevAcl, nullptr, &pSecurityDescriptor), L"GetNamedSecurityInfoW");

        ACL* newAcl = nullptr;
        CheckStatus(SetEntriesInAclW(1, &access, prevAcl, &newAcl), L"SetEntriesInAclW");
        CheckStatus(SetNamedSecurityInfoW(dir.data(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, newAcl, nullptr), L"SetNamedSecurityInfoW");
    }

    std::wstring cmdline = L"\"" + std::wstring(progid.c_str()) + L"\"";
    for (const auto& arg : args)
        cmdline += L" " + arg;

    PROCESS_INFORMATION pi = {};
    CheckWin32(CreateProcessW(progid.c_str(), cmdline.data(), nullptr, nullptr, false, EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr, &si.StartupInfo, &pi), L"CreateProcessW");
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}
