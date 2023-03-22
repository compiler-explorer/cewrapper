#include "../include/job.hpp"
#include "../include/checks.hpp"
#include <iostream>

std::wstring CreateJobName()
{
    std::wstring name = L"cejob";

    const int pid = GetCurrentProcessId();
    name.append(std::to_wstring(pid));

    return name;
}

cewrapper::Job::Job(const Config config) : config(config)
{
    this->name = CreateJobName();

    this->CreateJob();
}

cewrapper::Job::~Job()
{
    this->KillJob(9);
}

void cewrapper::Job::CreateJob()
{
    // https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects

    this->job = CreateJobObject(NULL, this->name.c_str());

    JOBOBJECTINFOCLASS infoclass = JOBOBJECTINFOCLASS::JobObjectExtendedLimitInformation;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION info{};

    // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_limit_information

    info.BasicLimitInformation.ActiveProcessLimit = config.pids_max;
    if (this->config.debugging)
        std::cerr << "Setting ActiveProcessLimit to " << info.BasicLimitInformation.ActiveProcessLimit << "\n";

    // PerJobUserTimeLimit is in "100-nanosecond ticks"
    info.BasicLimitInformation.PerJobUserTimeLimit.QuadPart = static_cast<int64_t>(config.time_limit_ms) * 10'000;
    if (this->config.debugging)
        std::cerr << "Setting PerJobUserTimeLimit to " << info.BasicLimitInformation.PerJobUserTimeLimit.QuadPart << "\n";

    info.JobMemoryLimit = config.mem_max;
    if (this->config.debugging)
        std::cerr << "Setting JobMemoryLimit to " << info.JobMemoryLimit << "\n";

    info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

    if (config.pids_max > 0)
        info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;

    if (config.time_limit_ms > 0)
        info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_TIME;

    if (config.mem_max > 0)
        info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_MEMORY;

    CheckWin32(SetInformationJobObject(this->job, infoclass, static_cast<void *>(&info), sizeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION)),
               L"SetInformationJobObject");
}

void cewrapper::Job::KillJob(UINT exitcode)
{
    TerminateJobObject(this->job, exitcode);
    CloseHandle(this->job);
}

void cewrapper::Job::AddProcess(HANDLE process) const
{
    AssignProcessToJobObject(this->job, process);
}
