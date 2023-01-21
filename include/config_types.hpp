#pragma once

#include <string>

namespace cewrapper
{

struct DirAccess
{
    std::wstring path;
    uint32_t rights;
};

enum class registry_type_t
{
    normal,
    wow6464,
    wow6432,
};

struct RegKeyAccess
{
    std::wstring path;
    uint32_t rights;
    registry_type_t type;
};

};
