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
    this->home_set = false;

    while (arg_idx < argc)
    {
        std::wstring_view arg = argv[arg_idx];

        if (arg.starts_with(L"--time_limit="))
        {
            this->time_limit_ms = svtoi(arg.substr(13)) * 1000;
            arg_idx++;
        }
        else if (arg.compare(L"-vv") == 0)
        {
            this->debugging = true;
            this->extra_debugging = true;
            arg_idx++;
        }
        else if (arg.compare(L"-v") == 0)
        {
            this->debugging = true;
            arg_idx++;
        }
        else if (arg.compare(L"--summary") == 0)
        {
            this->summary = true;
            arg_idx++;
        }
        else if (arg.starts_with(L"--config="))
        {
            this->loadFromFile(arg.substr(9));
            arg_idx++;
        }
        else if (arg.starts_with(L"--home="))
        {
            this->home = arg.substr(7);
            this->home_set = true;
            arg_idx++;
        }
        else if (arg.compare(L"--suspend") == 0)
        {
            this->suspend_after_start = true;
            arg_idx++;
        }
        else if (arg.compare(L"--wait") == 0)
        {
            this->wait_before_spawn = true;
            arg_idx++;
        }
        else
        {
            break;
        }
    }

    this->progid = argv[arg_idx];
    this->args.clear();
    arg_idx += 1;
    for (; arg_idx < argc; ++arg_idx)
        this->args.push_back(argv[arg_idx]);
}

std::wstring utf8str_to_wstr(std::string_view utf8str)
{
    size_t buffer_size = (utf8str.length() + 1) * sizeof(wchar_t);
    wchar_t *buffer = static_cast<wchar_t *>(malloc(buffer_size));
    if (buffer == nullptr)
        throw std::exception("Not enough memory to allocate a buffer");

    memset(buffer, 0, buffer_size);

    int convertedChars = MultiByteToWideChar(CP_UTF8, 0, utf8str.data(), static_cast<int>(utf8str.length()),
                                             reinterpret_cast<wchar_t *>(buffer), static_cast<int>(utf8str.length()));
    if (convertedChars <= 0)
        throw std::exception("Could not convert utf8 string");

    std::wstring newstr(buffer, convertedChars);

    free(buffer);

    return newstr;
}

void cewrapper::Config::loadFromFile(const std::wstring_view file)
{
    using json = nlohmann::json;

    std::ifstream jsonfile(file.data());
    json data = json::parse(jsonfile);

    this->use_appcontainer = data.value("use_appcontainer", true);

    this->mem_max = data.value("mem_max", 0);
    this->pids_max = data.value("pids_max", 0);

    for (auto &dir : data["allowed_paths"])
    {
        uint32_t rights{ GENERIC_READ };
        if (dir.value("rw", false))
            rights |= GENERIC_WRITE;

        if (!dir.value("noexec", false))
            rights |= GENERIC_EXECUTE;

        std::string path = dir["path"];

        if (path.empty())
            continue;

        if (path.length() >= MAXINT)
            continue;

        this->allowed_dirs.push_back({ .path = utf8str_to_wstr(path), .rights = rights });
    }

    for (auto &reg : data["allowed_registry"])
    {
        uint32_t rights{ GENERIC_READ };
        if (reg.value("rw", false))
            rights = GENERIC_ALL;

        registry_type_t regtype{};
        std::string jsregtype = reg.value("type", "normal");
        if (jsregtype.compare("wow6464"))
        {
            regtype = registry_type_t::wow6464;
        }
        else if (jsregtype.compare("wow6432"))
        {
            regtype = registry_type_t::wow6432;
        }

        std::string path = reg["path"];

        if (path.empty())
            continue;

        if (path.length() >= MAXINT)
            continue;

        this->allowed_registry.push_back({ .path = utf8str_to_wstr(path), .rights = rights, .type = regtype });
    }
}
