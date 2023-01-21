#pragma once

#include <string>
#include <vector>

namespace cewrapper
{

struct Config
{
    bool debugging{};
    int time_limit_ms{};
    int loopwait_ms{ 500 };
    std::wstring progid{};
    std::vector<std::wstring> args{};

    void initFromArguments(int argc, wchar_t *argv[]);

    static Config &get();
};

}; // namespace cewrapper
