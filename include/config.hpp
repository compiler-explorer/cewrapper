#pragma once

#include <string>
#include <vector>

#include "config_types.hpp"

namespace cewrapper
{

struct Config
{
    bool debugging{false};
    bool extra_debugging{false};
    bool suspend_after_start{};
    int time_limit_ms{};
    int loopwait_ms{ 500 };
    std::wstring progid{};
    std::wstring home{};
    bool home_set{};
    bool use_appcontainer{ true };
    bool wait_before_spawn{};

    int pids_max{};
    int64_t mem_max{};

    std::vector<std::wstring> args{};
    std::vector<DirAccess> allowed_dirs{};
    std::vector<RegKeyAccess> allowed_registry{};

    void initFromArguments(int argc, wchar_t *argv[]);

    static Config &get();

    private:
    void loadFromFile(const std::wstring_view file);
};

}; // namespace cewrapper
