#pragma once

#include "config.hpp"
#include <string>
#include <windows.h>

namespace cewrapper
{

class Job
{
    private:
    std::wstring name;
    const Config config;
    HANDLE job{};
    void CreateJob();
    void KillJob(UINT exitcode);
    void ReportOnJob();

    public:
    Job(const Config config);
    ~Job();

    void AddProcess(HANDLE process) const;
};

} // namespace cewrapper
