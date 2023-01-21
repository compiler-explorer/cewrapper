#pragma once

#include <windows.h>

namespace cewrapper
{

void OutputErrorMessage(DWORD err, const wchar_t *action);
void CheckWin32(BOOL res, const wchar_t *action);
void CheckStatus(DWORD status, const wchar_t *action);

}; // namespace cewrapper
