#include "../include/access.hpp"
#include "../include/checks.hpp"
#include <aclapi.h>
#include <iostream>
#include <sddl.h>
#include <vector>

// NUL resolves to the \Device\Null device object, so the SE_FILE_OBJECT named-object provider does not
// apply to it and its DACL has to be read and written through an open handle instead.
//
// The kernel recreates \Device\Null with a default security descriptor on every boot, and that default
// does not grant the AppContainer SIDs, so a sandboxed child that opens NUL (directly, or by redirecting
// its stdio there) fails with ERROR_ACCESS_DENIED. \Device\Null is machine wide and shared by every
// process, so this grants access to all app packages rather than to a single container SID: a per-run
// grant would race with concurrently running sandboxes and would leak an ACE for every crashed run.
//
// Must be run elevated (WRITE_DAC on \Device\Null), once per boot, before any sandboxed process starts.
void cewrapper::grant_access_to_nul_device()
{
    dump_nul_device_dacl(L"before");

    // S-1-15-2-1 is ALL APPLICATION PACKAGES, S-1-15-2-2 is ALL RESTRICTED APPLICATION PACKAGES (LPAC)
    PSID all_packages = nullptr;
    PSID all_restricted_packages = nullptr;
    cewrapper::CheckWin32(ConvertStringSidToSidW(L"S-1-15-2-1", &all_packages), L"ConvertStringSidToSidW(S-1-15-2-1)");
    cewrapper::CheckWin32(ConvertStringSidToSidW(L"S-1-15-2-2", &all_restricted_packages),
                          L"ConvertStringSidToSidW(S-1-15-2-2)");

    EXPLICIT_ACCESSW access[2] = {};
    for (auto &entry : access)
    {
        entry.grfAccessPermissions = GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE;
        entry.grfAccessMode = GRANT_ACCESS;
        entry.grfInheritance = NO_INHERITANCE;
        entry.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        entry.Trustee.TrusteeType = TRUSTEE_IS_GROUP;
    }
    access[0].Trustee.ptstrName = static_cast<wchar_t *>(all_packages);
    access[1].Trustee.ptstrName = static_cast<wchar_t *>(all_restricted_packages);

    HANDLE hnul = CreateFileW(L"\\\\.\\NUL", READ_CONTROL | WRITE_DAC,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0,
                              nullptr);
    cewrapper::CheckWin32(hnul != INVALID_HANDLE_VALUE, L"CreateFileW(\\\\.\\NUL)");

    DWORD sd_size = 0;
    GetKernelObjectSecurity(hnul, DACL_SECURITY_INFORMATION, nullptr, 0, &sd_size);
    std::vector<BYTE> sd_buffer(sd_size);
    cewrapper::CheckWin32(GetKernelObjectSecurity(hnul, DACL_SECURITY_INFORMATION, sd_buffer.data(), sd_size, &sd_size),
                          L"GetKernelObjectSecurity");

    BOOL dacl_present = FALSE;
    BOOL dacl_defaulted = FALSE;
    ACL *prevAcl = nullptr;
    cewrapper::CheckWin32(GetSecurityDescriptorDacl(sd_buffer.data(), &dacl_present, &prevAcl, &dacl_defaulted),
                          L"GetSecurityDescriptorDacl");

    // SetEntriesInAclW replaces any existing ACE for the same trustee, so re-running this is harmless
    ACL *newAcl = nullptr;
    cewrapper::CheckStatus(SetEntriesInAclW(2, access, dacl_present ? prevAcl : nullptr, &newAcl), L"SetEntriesInAclW");

    SECURITY_DESCRIPTOR newSd = {};
    cewrapper::CheckWin32(InitializeSecurityDescriptor(&newSd, SECURITY_DESCRIPTOR_REVISION),
                          L"InitializeSecurityDescriptor");
    cewrapper::CheckWin32(SetSecurityDescriptorDacl(&newSd, TRUE, newAcl, FALSE), L"SetSecurityDescriptorDacl");
    cewrapper::CheckWin32(SetKernelObjectSecurity(hnul, DACL_SECURITY_INFORMATION, &newSd), L"SetKernelObjectSecurity");

    LocalFree(newAcl);
    LocalFree(all_packages);
    LocalFree(all_restricted_packages);
    CloseHandle(hnul);

    // SetKernelObjectSecurity returning success is not proof the ACE landed on the device object, so
    // read it back through a fresh handle and print it
    dump_nul_device_dacl(L"after");
}

void cewrapper::dump_nul_device_dacl(const wchar_t *when)
{
    HANDLE hnul = CreateFileW(L"\\\\.\\NUL", READ_CONTROL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, 0, nullptr);
    if (hnul == INVALID_HANDLE_VALUE)
    {
        std::wcerr << L"NUL DACL (" << when << L"): could not open for READ_CONTROL, err=" << GetLastError() << L"\n";
        return;
    }

    DWORD sd_size = 0;
    GetKernelObjectSecurity(hnul, DACL_SECURITY_INFORMATION, nullptr, 0, &sd_size);
    std::vector<BYTE> sd_buffer(sd_size);
    if (!GetKernelObjectSecurity(hnul, DACL_SECURITY_INFORMATION, sd_buffer.data(), sd_size, &sd_size))
    {
        std::wcerr << L"NUL DACL (" << when << L"): GetKernelObjectSecurity failed, err=" << GetLastError() << L"\n";
        CloseHandle(hnul);
        return;
    }

    wchar_t *sddl = nullptr;
    if (ConvertSecurityDescriptorToStringSecurityDescriptorW(sd_buffer.data(), SDDL_REVISION_1,
                                                             DACL_SECURITY_INFORMATION, &sddl, nullptr))
    {
        std::wcerr << L"NUL DACL (" << when << L"): " << sddl << L"\n";
        LocalFree(sddl);
    }

    CloseHandle(hnul);
}

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
