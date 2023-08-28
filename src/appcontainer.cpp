#include "../include/appcontainer.hpp"
#include "../include/checks.hpp"
#include <iostream>

#include <lsalookup.h>
#include <ntsecapi.h>

void CreateCapabilitySID(PSID_AND_ATTRIBUTES sids, size_t idx, WELL_KNOWN_SID_TYPE sidtype)
{
    sids[idx].Attributes = SE_GROUP_ENABLED;

    // https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createwellknownsid
    // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-well_known_sid_type

    DWORD sidsize = 68;
    sids[idx].Sid = static_cast<PSID>(malloc(sidsize));

    BOOL err = CreateWellKnownSid(sidtype, nullptr, sids[idx].Sid, &sidsize);
    if (err == 0)
    {
        cewrapper::OutputErrorMessage(GetLastError(), L"CreateWellKnownSid");
        abort();
    }
}

void cewrapper::AppContainer::CreateContainer()
{
    sec_cap.Capabilities = new SID_AND_ATTRIBUTES[1];
    sec_cap.CapabilityCount = 1;

    CreateCapabilitySID(sec_cap.Capabilities, 0, WinCapabilityPrivateNetworkClientServerSid);

    HRESULT hr = CreateAppContainerProfile(this->name.c_str(), L"cesandbox", L"cesandbox", sec_cap.Capabilities,
                                           sec_cap.CapabilityCount, &sec_cap.AppContainerSid);
    if (HRESULT_CODE(hr) == ERROR_ALREADY_EXISTS)
    {
       // todo: should actually delete it first, because we recreate it each time...
        if (config.extra_debugging)
           std::wcerr << "CreateAppContainerProfile - ALREADY_EXISTS, deriving from profile\n";
        hr = DeriveAppContainerSidFromAppContainerName(L"cesandbox", &sec_cap.AppContainerSid);
    }

    if (FAILED(hr))
    {
        if (config.debugging) {
            std::wcerr << "CreateAppContainerProfile or DeriveAppContainerSidFromAppContainerName - Failed with " << hr << "\n";

            if (config.extra_debugging)
                OutputErrorMessage(GetLastError(), L"CreateAppContainerProfile");
        }
        abort();
    }
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
