#pragma once

#include <string>
#include <vector>

#include "config_types.hpp"

namespace cewrapper
{

struct Config
{
    bool debugging{};
    bool extra_debugging{};
    int time_limit_ms{};
    int loopwait_ms{ 500 };
    std::wstring progid{};
    std::wstring home{};
    bool home_set{};
    bool use_appcontainer{true};
    std::vector<std::wstring> args{};
    std::vector<DirAccess> allowed_dirs{};
    std::vector<RegKeyAccess> allowed_registry{};

    void initFromArguments(int argc, wchar_t *argv[]);

    static Config &get();

private:
    void loadFromFile(const std::wstring_view file);
};

}; // namespace cewrapper
