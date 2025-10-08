#include "../include/access.hpp"
#include "../include/checks.hpp"
#include <aclapi.h>

void cewrapper::grant_access_to_path(wchar_t *container_sid, wchar_t *dir, uint32_t permissions)
{
    EXPLICIT_ACCESSW access = {};
    {
        access.grfAccessPermissions = permissions;
        access.grfAccessMode = GRANT_ACCESS;
        access.grfInheritance = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
        access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        access.Trustee.TrusteeType = TRUSTEE_IS_GROUP;
        access.Trustee.ptstrName = container_sid;
    }

    PSECURITY_DESCRIPTOR pSecurityDescriptor = nullptr;
    ACL *prevAcl = nullptr;
    cewrapper::CheckStatus(GetNamedSecurityInfoW(dir, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr,
                                                 nullptr, &prevAcl, nullptr, &pSecurityDescriptor),
                           L"GetNamedSecurityInfoW");

    ACL *newAcl = nullptr;
    cewrapper::CheckStatus(SetEntriesInAclW(1, &access, prevAcl, &newAcl), L"SetEntriesInAclW");
    cewrapper::CheckStatusAllowFail(SetNamedSecurityInfoW(dir, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, newAcl, nullptr),
                           L"SetNamedSecurityInfoW");
}

void cewrapper::allow_access_to_nul()
{
    wchar_t allpack[] = L"ALL APPLICATION PACKAGES\0";
    EXPLICIT_ACCESSW access = {};
    {
        access.grfAccessPermissions = GENERIC_READ | GENERIC_WRITE;
        access.grfAccessMode = GRANT_ACCESS;
        access.grfInheritance = NO_INHERITANCE;
        access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        access.Trustee.TrusteeType = TRUSTEE_IS_GROUP;
        access.Trustee.ptstrName = allpack;
    }

    wchar_t path[] = L"\\\\.\\NUL";
    PSECURITY_DESCRIPTOR pSecurityDescriptor = nullptr;
    ACL *prevAcl = nullptr;
    cewrapper::CheckStatus(GetNamedSecurityInfoW(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr,
                                                 nullptr, &prevAcl, nullptr, &pSecurityDescriptor),
                           L"GetNamedSecurityInfoW");

    ACL *newAcl = nullptr;
    cewrapper::CheckStatus(SetEntriesInAclW(1, &access, prevAcl, &newAcl), L"SetEntriesInAclW");
    cewrapper::CheckStatusAllowFail(SetNamedSecurityInfoW(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, newAcl, nullptr),
                           L"SetNamedSecurityInfoW");
}

void cewrapper::remove_access_to_path(wchar_t *container_sid, wchar_t *dir, uint32_t permissions)
{
    EXPLICIT_ACCESSW access = {};
    {
        access.grfAccessPermissions = permissions;
        access.grfAccessMode = REVOKE_ACCESS;
        access.grfInheritance = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
        access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        access.Trustee.TrusteeType = TRUSTEE_IS_GROUP;
        access.Trustee.ptstrName = container_sid;
    }

    PSECURITY_DESCRIPTOR pSecurityDescriptor = nullptr;
    ACL *prevAcl = nullptr;
    cewrapper::CheckStatus(GetNamedSecurityInfoW(dir, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr,
                                                 &prevAcl, nullptr, &pSecurityDescriptor),
                           L"GetNamedSecurityInfoW");

    ACL *newAcl = nullptr;
    cewrapper::CheckStatus(SetEntriesInAclW(1, &access, prevAcl, &newAcl), L"SetEntriesInAclW");
    cewrapper::CheckStatusAllowFail(SetNamedSecurityInfoW(dir, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr,
                                                          nullptr, newAcl, nullptr),
                           L"SetNamedSecurityInfoW");
}

void cewrapper::grant_access_to_registry(wchar_t *container_sid, wchar_t *key, uint32_t permissions, registry_type_t regtype)
{
    EXPLICIT_ACCESSW access = {};
    {
        access.grfAccessPermissions = permissions;
        access.grfAccessMode = GRANT_ACCESS;
        access.grfInheritance = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
        access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        access.Trustee.TrusteeType = TRUSTEE_IS_GROUP;
        access.Trustee.ptstrName = container_sid;
    }

    SE_OBJECT_TYPE seObjType;
    switch (regtype)
    {
    case registry_type_t::normal:
        seObjType = SE_REGISTRY_KEY;
        break;
    case registry_type_t::wow6464:
        seObjType = SE_REGISTRY_WOW64_64KEY;
        break;
    case registry_type_t::wow6432:
        seObjType = SE_REGISTRY_WOW64_32KEY;
        break;
    default:
        throw new std::exception("Bad registry type");
    }

    PSECURITY_DESCRIPTOR pSecurityDescriptor = nullptr;
    ACL *prevAcl = nullptr;
    cewrapper::CheckStatus(GetNamedSecurityInfoW(key, seObjType, DACL_SECURITY_INFORMATION, nullptr, nullptr,
                                                 &prevAcl, nullptr, &pSecurityDescriptor),
                           L"GetNamedSecurityInfoW");

    ACL *newAcl = nullptr;
    cewrapper::CheckStatus(SetEntriesInAclW(1, &access, prevAcl, &newAcl), L"SetEntriesInAclW");
    cewrapper::CheckStatus(SetNamedSecurityInfoW(key, seObjType, DACL_SECURITY_INFORMATION, nullptr, nullptr, newAcl, nullptr),
                           L"SetNamedSecurityInfoW");
}
