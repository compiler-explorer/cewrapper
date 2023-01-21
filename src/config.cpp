#include "../include/config.hpp"

cewrapper::Config _main_config;

cewrapper::Config &cewrapper::Config::get()
{
    return _main_config;
}

inline int svtoi(const std::wstring_view sv)
{
    // std::from_chars() doesn't seem to have a wchar version, so I guess this will have to do
    const std::wstring temp(sv.data());
    return std::stoi(temp);
}

void cewrapper::Config::initFromArguments(int argc, wchar_t *argv[])
{
    int arg_idx = 1;

    while (arg_idx < argc)
    {
        std::wstring_view arg = argv[arg_idx];

        if (arg.starts_with(L"--time_limit="))
        {
            cewrapper::Config::get().time_limit_ms = svtoi(arg.substr(13)) * 1000;
            arg_idx++;
        }
        else if (arg.compare(L"-v") == 0)
        {
            cewrapper::Config::get().debugging = true;
            arg_idx++;
        }
        else
        {
            break;
        }
    }

    cewrapper::Config::get().progid = argv[arg_idx];
    cewrapper::Config::get().args.clear();
    for (; arg_idx < argc; ++arg_idx)
        cewrapper::Config::get().args.push_back(argv[arg_idx]);
}
