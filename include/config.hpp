#pragma once

#include <string>
#include <vector>

namespace cewrapper
{

struct DirAccess
{
    std::wstring path;
    uint32_t rights;
};

struct Config
{
    bool debugging{};
    bool extra_debugging{};
    int time_limit_ms{};
    int loopwait_ms{ 500 };
    std::wstring progid{};
    std::vector<std::wstring> args{};
    std::vector<DirAccess> allowed_dirs{};

    void initFromArguments(int argc, wchar_t *argv[]);

    static Config &get();

private:
    void loadFromFile(const std::wstring_view file);
};

}; // namespace cewrapper
