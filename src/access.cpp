#include "../include/access.hpp"
#include "../include/checks.hpp"
#include <aclapi.h>

void cewrapper::grant_access(wchar_t *container_sid, wchar_t *dir, uint32_t permissions)
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
    cewrapper::CheckStatus(SetNamedSecurityInfoW(dir, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, newAcl, nullptr),
                           L"SetNamedSecurityInfoW");
}
