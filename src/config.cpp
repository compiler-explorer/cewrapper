#include "../include/config.hpp"
#include <fstream>
#include <nlohmann/json.hpp>
#include <windows.h>

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
            this->time_limit_ms = svtoi(arg.substr(13)) * 1000;
            arg_idx++;
        }
        else if (arg.compare(L"-v") == 0)
        {
            this->debugging = true;
            arg_idx++;
        }
        else if (arg.starts_with(L"--config="))
        {
            this->loadFromFile(arg.substr(9));
            arg_idx++;
        }
        else
        {
            break;
        }
    }

    this->progid = argv[arg_idx];
    this->args.clear();
    for (; arg_idx < argc; ++arg_idx)
        this->args.push_back(argv[arg_idx]);
}

void cewrapper::Config::loadFromFile(const std::wstring_view file)
{
    using json = nlohmann::json;

    std::ifstream jsonfile(file);
    json data = json::parse(jsonfile);

    auto allowed = data["allowed"];
    for (auto dir : allowed)
    {
        uint32_t rights{ GENERIC_READ };
        if (dir["rw"])
            rights |= GENERIC_WRITE;

        if (!dir["noexec"])
            rights |= GENERIC_EXECUTE;

        std::string path = dir["path"];

        if (path.empty())
            continue;

        if (path.length() >= MAXINT)
            continue;

        // assume json file is in utf8
        wchar_t *buffer = static_cast<wchar_t *>(malloc(path.length()));
        int convertedChars = MultiByteToWideChar(CP_UTF8, 0, path.data(), static_cast<int>(path.length() / sizeof(wchar_t)), reinterpret_cast<wchar_t *>(buffer), static_cast<int>(path.length()));
        if (convertedChars <= 0)
            throw std::exception("Could not read utf8 path from json file");

        this->allowed_dirs.push_back({.path = std::wstring(buffer, convertedChars), .rights = rights});

        free(buffer);
    }
}
