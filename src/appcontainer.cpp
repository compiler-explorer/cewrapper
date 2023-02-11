#include "../include/appcontainer.hpp"
#include <iostream>

void cewrapper::AppContainer::CreateContainer()
{
    // todo: make unique name
    HRESULT hr = CreateAppContainerProfile(L"cesandbox", L"cesandbox", L"cesandbox", nullptr, 0, &sec_cap.AppContainerSid);
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
    HRESULT hr = DeleteAppContainerProfile(L"cesandbox");
    if (FAILED(hr))
    {
        if (config.debugging)
            std::wcerr << "DeleteAppContainerProfile - Failed with " << hr << "\n";
    }
}

cewrapper::AppContainer::AppContainer(const Config config) : config(config)
{
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
