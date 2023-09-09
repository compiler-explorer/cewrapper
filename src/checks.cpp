#include "../include/checks.hpp"
#include "../include/config.hpp"
#include <iostream>

void cewrapper::OutputErrorMessage(DWORD err, const wchar_t *action)
{
    LPTSTR errorText = nullptr;
    DWORD len = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS,
                               nullptr, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&errorText, 0, nullptr);

    if (len)
    {
        if (cewrapper::Config::get().debugging)
        {
            std::wcerr << L"ERROR: " << action << L" - " << errorText << L"\n";
        }
        else
        {
            std::wcerr << L"ERROR: " << errorText << L"\n";
        }
    }
    else
    {
        std::wcerr << L"ERROR: unknown" << L"\n";
    }
}

void cewrapper::CheckWin32(BOOL res, const wchar_t *action)
{
    if (res)
        return;

    OutputErrorMessage(GetLastError(), action);

    throw std::exception("abort");
}

void cewrapper::CheckStatus(DWORD status, const wchar_t *action)
{
    if (status == ERROR_SUCCESS)
        return;

    OutputErrorMessage(status, action);
    throw std::exception("abort");
}

void cewrapper::CheckStatusAllowFail(DWORD status, const wchar_t *action)
{
    if (status == ERROR_SUCCESS)
        return;

    OutputErrorMessage(status, action);
}
