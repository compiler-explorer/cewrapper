#pragma once

#include <string>
#include <userenv.h>
#include "config.hpp"

namespace cewrapper
{

class AppContainer
{
    private:
    std::wstring name;
    const Config config;
    SECURITY_CAPABILITIES sec_cap = {};
    void CreateContainer();
    void DestroyContainer();

    public:
    AppContainer(const Config config);
    ~AppContainer();


    wchar_t *getSid() const;
    void *getSecurityCapabilitiesPtr();
};

}; // namespace cewrapper
