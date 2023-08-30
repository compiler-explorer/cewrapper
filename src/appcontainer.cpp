#include "../include/appcontainer.hpp"
#include "../include/checks.hpp"
#include <iostream>

#include <lsalookup.h>
#include <ntsecapi.h>

// https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-derivecapabilitysidsfromname
typedef BOOL(WINAPI *DeriveCapabilitySidsFromNameImpl)(LPCWSTR CapName,
                                                       PSID **CapabilityGroupSids,
                                                       DWORD *CapabilityGroupSidCount,
                                                       PSID **CapabilitySids,
                                                       DWORD *CapabilitySidCount);

DeriveCapabilitySidsFromNameImpl _DeriveCapabilitySidsFromName = 
    reinterpret_cast<DeriveCapabilitySidsFromNameImpl>(GetProcAddress(GetModuleHandle(L"KernelBase.dll"), "DeriveCapabilitySidsFromName"));

struct CapSidsArray
{
    public:
    PSID *sids = nullptr;
    DWORD count = 0;

    ~CapSidsArray()
    {
        for (size_t i = 0; i < count; i++)
        {
            LocalFree(sids[i]);
        }
        LocalFree(sids);
    }
};

void CreateCapabilitySID(PSID_AND_ATTRIBUTES sids, size_t idx, WELL_KNOWN_SID_TYPE sidtype)
{
    sids[idx].Attributes = SE_GROUP_ENABLED;

    // https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createwellknownsid
    // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-well_known_sid_type

    DWORD sidsize = SECURITY_MAX_SID_SIZE;
    sids[idx].Sid = static_cast<PSID>(malloc(sidsize));

    BOOL err = CreateWellKnownSid(sidtype, nullptr, sids[idx].Sid, &sidsize);
    if (err == 0)
    {
        cewrapper::OutputErrorMessage(GetLastError(), L"CreateWellKnownSid");
        abort();
    }
}

void CreateCapabilitySIDFromName(PSID_AND_ATTRIBUTES sids, size_t idx, std::wstring name)
{
    CapSidsArray groupSidsArr;
    CapSidsArray sidsArr;

    cewrapper::CheckWin32(_DeriveCapabilitySidsFromName(name.c_str(), &groupSidsArr.sids, &groupSidsArr.count, &sidsArr.sids,
                                             &sidsArr.count),
               L"_DeriveCapabilitySidsFromName");

    if (sidsArr.count == 0)
    {
        std::wcerr << L"_DeriveCapabilitySidsFromName returned an empty SID array\n";
        abort();
    }

    DWORD sidsize = SECURITY_MAX_SID_SIZE;
    sids[idx].Sid = static_cast<PSID>(malloc(sidsize));
    sids[idx].Attributes = SE_GROUP_ENABLED;

    CopySid(sidsize, sids[idx].Sid, sidsArr.sids[0]);
}

void cewrapper::AppContainer::InitializeCapabilities()
{
    sec_cap.Capabilities = new SID_AND_ATTRIBUTES[1];
    sec_cap.CapabilityCount = 1;

    // https://learn.microsoft.com/en-us/previous-versions/windows/apps/hh780593(v=win.10)#diagnostic-tool-for-network-isolation
    // CreateCapabilitySID(sec_cap.Capabilities, 0, WinCapabilityInternetClientSid);
    // CreateCapabilitySID(sec_cap.Capabilities, 0, WinCapabilityInternetClientServerSid);
    // CreateCapabilitySID(sec_cap.Capabilities, 0, WinCapabilityPrivateNetworkClientServerSid);


    // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55
    // 0xC0000201
    // STATUS_NETWORK_OPEN_RESTRICTION
    // A remote open failed because the network open restrictions were not satisfied.

    CreateCapabilitySIDFromName(sec_cap.Capabilities, 0, L"remoteFileAccess");
}

void cewrapper::AppContainer::CreateContainer()
{
    this->InitializeCapabilities();

    HRESULT hr = CreateAppContainerProfile(this->name.c_str(), L"cesandbox", L"cesandbox", sec_cap.Capabilities,
                                           sec_cap.CapabilityCount, &sec_cap.AppContainerSid);
    if (HRESULT_CODE(hr) == ERROR_ALREADY_EXISTS)
    {
        if (config.debugging)
            std::wcerr << "AppContainer " << this->name.c_str() << " somehow already existed, deleting and recreating...\n";
        // this really should not be happening. Only happens in case of weird crash and if we get the exact same PID
        this->DestroyContainer();
        hr = CreateAppContainerProfile(this->name.c_str(), L"cesandbox", L"cesandbox", sec_cap.Capabilities,
                                               sec_cap.CapabilityCount, &sec_cap.AppContainerSid);
    }

    if (FAILED(hr))
    {
        if (config.debugging) {
            std::wcerr << "CreateAppContainerProfile - Failed with " << hr << "\n";

            if (config.extra_debugging)
                OutputErrorMessage(GetLastError(), L"CreateAppContainerProfile");
        }
        abort();
    }

    if (config.debugging)
        std::wcerr << "AppContainer created: " << this->name.c_str() << "\n";
}

void cewrapper::AppContainer::DestroyContainer()
{
    HRESULT hr = DeleteAppContainerProfile(this->name.c_str());
    if (FAILED(hr))
    {
        if (config.debugging)
            std::wcerr << "DeleteAppContainerProfile - Failed with " << hr << "\n";

        // documentation says to call it again when it fails https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-deleteappcontainerprofile
        DeleteAppContainerProfile(this->name.c_str());
    }
}

std::wstring CreateSandboxName()
{
    std::wstring name = L"cesandbox";

    const int pid = GetCurrentProcessId();
    name.append(std::to_wstring(pid));

    return name;
}

cewrapper::AppContainer::AppContainer(const Config config) : config(config)
{
    this->name = CreateSandboxName();

    this->CreateContainer();
}

cewrapper::AppContainer::~AppContainer()
{
    this->DestroyContainer();
}

wchar_t *cewrapper::AppContainer::getSid() const
{
    return static_cast<wchar_t *>(this->sec_cap.AppContainerSid);
}

void *cewrapper::AppContainer::getSecurityCapabilitiesPtr()
{
    return reinterpret_cast<void *>(&this->sec_cap);
}
