#pragma once

#include <string_view>

namespace cewrapper
{

   void grant_access(wchar_t *container_sid, wchar_t *dir, uint32_t permissions);

};
