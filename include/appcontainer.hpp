#pragma once

#include <userenv.h>
#include "config.hpp"

namespace cewrapper
{

class AppContainer
{
    private:
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
