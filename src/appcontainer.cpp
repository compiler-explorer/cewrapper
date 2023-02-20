#include "../include/appcontainer.hpp"
#include <iostream>

void cewrapper::AppContainer::CreateContainer()
{
    HRESULT hr = CreateAppContainerProfile(this->name.c_str(), L"cesandbox", L"cesandbox", nullptr, 0, &sec_cap.AppContainerSid);
    if (HRESULT_CODE(hr) == ERROR_ALREADY_EXISTS)
    {
        if (config.extra_debugging)
            std::wcout << "CreateAppContainerProfile - ALREADY_EXISTS, deriving from profile\n";
        hr = DeriveAppContainerSidFromAppContainerName(L"cesandbox", &sec_cap.AppContainerSid);
    }

    if (FAILED(hr))
    {
        if (config.debugging)
            std::wcerr << "CreateAppContainerProfile or DeriveAppContainerSidFromAppContainerName - Failed with " << hr << "\n";
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
