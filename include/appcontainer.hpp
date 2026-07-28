#pragma once

#include <string>
#include <userenv.h>
#include <vector>
#include "config.hpp"

namespace cewrapper
{

class AppContainer
{
    private:
    std::wstring name;
    const Config config;
    SECURITY_CAPABILITIES sec_cap = {};
    // backing storage for sec_cap.Capabilities, must outlive sec_cap's use
    std::vector<SID_AND_ATTRIBUTES> capabilities;
    void CreateContainer();
    void DestroyContainer();
    void InitializeCapabilities();

    public:
    AppContainer(const Config config);
    ~AppContainer();


    wchar_t *getSid() const;
    void *getSecurityCapabilitiesPtr();
};

}; // namespace cewrapper
