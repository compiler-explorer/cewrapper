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

void AddCapabilitySID(std::vector<SID_AND_ATTRIBUTES> &sids, WELL_KNOWN_SID_TYPE sidtype)
{
    SID_AND_ATTRIBUTES &sid = sids.emplace_back();
    sid.Attributes = SE_GROUP_ENABLED;

    // https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createwellknownsid
    // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-well_known_sid_type

    DWORD sidsize = SECURITY_MAX_SID_SIZE;
    sid.Sid = static_cast<PSID>(malloc(sidsize));

    BOOL err = CreateWellKnownSid(sidtype, nullptr, sid.Sid, &sidsize);
    if (err == 0)
    {
        cewrapper::OutputErrorMessage(GetLastError(), L"CreateWellKnownSid");
        abort();
    }
}

void AddCapabilitySIDFromName(std::vector<SID_AND_ATTRIBUTES> &sids, std::wstring name)
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
    SID_AND_ATTRIBUTES &sid = sids.emplace_back();
    sid.Sid = static_cast<PSID>(malloc(sidsize));
    sid.Attributes = SE_GROUP_ENABLED;

    CopySid(sidsize, sid.Sid, sidsArr.sids[0]);
}

void cewrapper::AppContainer::InitializeCapabilities()
{
    // Each Add* call appends one capability; the count below is derived from the
    // list, so capabilities can be added or removed without keeping indices and a
    // hardcoded count in sync.
    capabilities.clear();

    // https://learn.microsoft.com/en-us/previous-versions/windows/apps/hh780593(v=win.10)#diagnostic-tool-for-network-isolation
    // AddCapabilitySID(capabilities, WinCapabilityInternetClientSid);
    // AddCapabilitySID(capabilities, WinCapabilityInternetClientServerSid);
    // AddCapabilitySID(capabilities, WinCapabilityPrivateNetworkClientServerSid);


    // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55
    // 0xC0000201
    // STATUS_NETWORK_OPEN_RESTRICTION
    // A remote open failed because the network open restrictions were not satisfied.

    AddCapabilitySIDFromName(capabilities, L"remoteFileAccess");

    sec_cap.Capabilities = capabilities.data();
    sec_cap.CapabilityCount = static_cast<DWORD>(capabilities.size());
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
