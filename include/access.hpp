#pragma once

#include <string_view>
#include "config_types.hpp"

namespace cewrapper
{

void grant_access_to_path(wchar_t *container_sid, wchar_t *dir, uint32_t permissions);
void grant_access_to_registry(wchar_t *container_sid, wchar_t *key, uint32_t permissions, registry_type_t regtype);

void remove_access_to_path(wchar_t *container_sid, wchar_t *dir, uint32_t permissions);

};
