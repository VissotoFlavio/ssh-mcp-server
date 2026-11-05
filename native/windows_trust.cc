#include <node_api.h>

#include <windows.h>
#include <winternl.h>
#include <bcrypt.h>
#include <aclapi.h>
#include <sddl.h>
#include <softpub.h>
#include <mscat.h>
#include <wincrypt.h>
#include <wincred.h>
#include <wintrust.h>
#include <winver.h>

#include <string>
#include <array>
#include <algorithm>
#include <climits>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <vector>

namespace {

constexpr wchar_t kConfigurationKey[] = L"Software\\Vissoto\\ssh-mcp-server";
constexpr wchar_t kStateFile[] = L"connection-profiles.json";
constexpr DWORD kMaxFileBytes = 1024 * 1024;
constexpr wchar_t kCredentialTargetPrefix[] = L"Vissoto/ssh-mcp-server/";

#ifdef SSH_MCP_NATIVE_TEST
PSID g_test_system_owner = nullptr;
const std::wstring* g_test_system_directory = nullptr;
bool (*g_test_protected_file_pre_recheck)() = nullptr;
bool g_test_protected_file_replacement_succeeded = false;
DWORD g_test_protected_file_replacement_error = ERROR_SUCCESS;
bool (*g_test_openssh_pre_launch)(const std::wstring& ssh_add) = nullptr;
std::wstring g_test_replacement_root;
std::wstring g_test_replacement_leaf;
bool g_test_replacement_is_root = false;
bool g_test_openssh_replacement_attempted = false;
bool g_test_openssh_replacement_move_attempted = false;
bool g_test_openssh_replacement_succeeded = false;
bool g_test_openssh_force_unexpected_replacement_error = false;
DWORD g_test_openssh_replacement_error = ERROR_SUCCESS;
#endif

class Handle final {
 public:
  explicit Handle(HANDLE value = INVALID_HANDLE_VALUE) : value_(value) {}
  ~Handle() { if (value_ != INVALID_HANDLE_VALUE) CloseHandle(value_); }
  Handle(const Handle&) = delete;
  Handle& operator=(const Handle&) = delete;
  Handle(Handle&& other) noexcept : value_(other.value_) { other.value_ = INVALID_HANDLE_VALUE; }
  Handle& operator=(Handle&& other) noexcept {
    if (this != &other) {
      if (value_ != INVALID_HANDLE_VALUE) CloseHandle(value_);
      value_ = other.value_;
      other.value_ = INVALID_HANDLE_VALUE;
    }
    return *this;
  }
  HANDLE get() const { return value_; }
  void reset(HANDLE value = INVALID_HANDLE_VALUE) {
    if (value_ != INVALID_HANDLE_VALUE) CloseHandle(value_);
    value_ = value;
  }
 private:
  HANDLE value_;
};

class RegistryKey final {
 public:
  explicit RegistryKey(HKEY value = nullptr) : value_(value) {}
  ~RegistryKey() { if (value_ != nullptr) RegCloseKey(value_); }
  RegistryKey(const RegistryKey&) = delete;
  HKEY get() const { return value_; }
 private:
  HKEY value_;
};

napi_value Unavailable(napi_env env) {
  napi_throw_error(env, nullptr, "Windows secure storage is unavailable");
  return nullptr;
}

bool IsWellKnown(PSID sid, WELL_KNOWN_SID_TYPE type) {
  DWORD size = SECURITY_MAX_SID_SIZE;
  BYTE buffer[SECURITY_MAX_SID_SIZE];
  return CreateWellKnownSid(type, nullptr, buffer, &size) && EqualSid(sid, buffer);
}

bool IsTrustedSid(PSID sid, PSID operator_sid) {
  return EqualSid(sid, operator_sid) || IsWellKnown(sid, WinLocalSystemSid) || IsWellKnown(sid, WinBuiltinAdministratorsSid);
}

bool IsTrustedSystemSid(PSID sid) {
#ifdef SSH_MCP_NATIVE_TEST
  if (g_test_system_owner != nullptr && EqualSid(sid, g_test_system_owner)) return true;
#endif
  static const wchar_t kTrustedInstallerSid[] = L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
  PSID trusted_installer = nullptr;
  const bool converted = ConvertStringSidToSidW(kTrustedInstallerSid, &trusted_installer) != 0;
  const bool trusted = IsWellKnown(sid, WinLocalSystemSid) || IsWellKnown(sid, WinBuiltinAdministratorsSid) || (converted && EqualSid(sid, trusted_installer));
  if (trusted_installer != nullptr) LocalFree(trusted_installer);
  return trusted;
}

bool IsSafeDacl(PACL dacl, PSID operator_sid, const GENERIC_MAPPING& mapping, ACCESS_MASK mutation_rights) {
  if (dacl == nullptr) return false;
  ACL_SIZE_INFORMATION info{};
  if (!GetAclInformation(dacl, &info, sizeof(info), AclSizeInformation)) return false;
  for (DWORD index = 0; index < info.AceCount; ++index) {
    void* raw_ace = nullptr;
    if (!GetAce(dacl, index, &raw_ace)) return false;
    auto* header = static_cast<ACE_HEADER*>(raw_ace);
    if ((header->AceFlags & INHERIT_ONLY_ACE) != 0) continue;
    if (header->AceType == ACCESS_DENIED_ACE_TYPE) continue;
    if (header->AceType != ACCESS_ALLOWED_ACE_TYPE) return false;
    auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(raw_ace);
    ACCESS_MASK mask = ace->Mask;
    MapGenericMask(&mask, const_cast<GENERIC_MAPPING*>(&mapping));
    PSID sid = reinterpret_cast<PSID>(&ace->SidStart);
    if (!IsTrustedSid(sid, operator_sid) && (mask & mutation_rights) != 0) return false;
  }
  return true;
}

bool ReadStringValue(HKEY key, const wchar_t* name, std::wstring* value) {
  DWORD type = 0;
  DWORD bytes = 0;
  if (RegGetValueW(key, nullptr, name, RRF_RT_REG_SZ, &type, nullptr, &bytes) != ERROR_SUCCESS || bytes < sizeof(wchar_t) || bytes > 64 * 1024) return false;
  std::vector<wchar_t> buffer(bytes / sizeof(wchar_t));
  if (RegGetValueW(key, nullptr, name, RRF_RT_REG_SZ, &type, buffer.data(), &bytes) != ERROR_SUCCESS) return false;
  if (buffer.back() != L'\0') return false;
  value->assign(buffer.data());
  return !value->empty() && value->find(L'\0') == std::wstring::npos;
}

bool IsAbsoluteLocalPath(const std::wstring& path) {
  return path.size() >= 4 && path[1] == L':' && (path[2] == L'\\' || path[2] == L'/') && path.rfind(L"\\\\", 0) != 0 && path.find(L":", 2) == std::wstring::npos;
}

bool IsLocalNtfsPath(const std::wstring& path) {
  if (!IsAbsoluteLocalPath(path) || GetDriveTypeW(path.substr(0, 3).c_str()) != DRIVE_FIXED) return false;
  wchar_t device[1024]{};
  const std::wstring drive = path.substr(0, 2);
  const DWORD device_size = QueryDosDeviceW(drive.c_str(), device, 1024);
  if (device_size == 0 || wcsncmp(device, L"\\??\\", 4) == 0 || wcsncmp(device, L"\\DosDevices\\", 12) == 0) return false;
  wchar_t filesystem[MAX_PATH]{};
  return GetVolumeInformationW(path.substr(0, 3).c_str(), nullptr, 0, nullptr, nullptr, nullptr, filesystem, MAX_PATH) && _wcsicmp(filesystem, L"NTFS") == 0;
}

bool IsSameOrNestedPath(const std::wstring& left, const std::wstring& right) {
  if (left.size() > right.size() || _wcsnicmp(left.c_str(), right.c_str(), left.size()) != 0) return false;
  return left.size() == right.size() || left.back() == L'\\' || right[left.size()] == L'\\';
}

bool CurrentUserSid(std::vector<BYTE>* sid) {
  HANDLE raw_token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw_token)) return false;
  Handle token(raw_token);
  DWORD bytes = 0;
  GetTokenInformation(token.get(), TokenUser, nullptr, 0, &bytes);
  if (bytes == 0) return false;
  std::vector<BYTE> buffer(bytes);
  if (!GetTokenInformation(token.get(), TokenUser, buffer.data(), bytes, &bytes)) return false;
  auto* user = reinterpret_cast<TOKEN_USER*>(buffer.data());
  const DWORD sid_bytes = GetLengthSid(user->User.Sid);
  sid->assign(static_cast<BYTE*>(user->User.Sid), static_cast<BYTE*>(user->User.Sid) + sid_bytes);
  return true;
}

bool VerifyRegistryConfiguration(HKEY key, PSID operator_sid) {
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  PSID owner = nullptr;
  PACL dacl = nullptr;
  const DWORD result = GetSecurityInfo(key, SE_REGISTRY_KEY, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, nullptr, &dacl, nullptr, &descriptor);
  if (result != ERROR_SUCCESS || descriptor == nullptr || owner == nullptr) { if (descriptor != nullptr) LocalFree(descriptor); return false; }
  SECURITY_DESCRIPTOR_CONTROL control = 0;
  DWORD revision = 0;
  const bool protected_dacl = GetSecurityDescriptorControl(descriptor, &control, &revision) && (control & SE_DACL_PROTECTED) != 0;
  GENERIC_MAPPING mapping{KEY_READ, KEY_WRITE, KEY_EXECUTE, KEY_ALL_ACCESS};
  const ACCESS_MASK mutation = KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_CREATE_LINK | DELETE | WRITE_DAC | WRITE_OWNER;
  const bool safe = EqualSid(owner, operator_sid) && protected_dacl && IsSafeDacl(dacl, operator_sid, mapping, mutation);
  LocalFree(descriptor);
  return safe;
}

bool RootsAreDistinct(const std::wstring& state_root, const std::wstring& known_hosts_root, PSID operator_sid);

bool LoadConfiguration(std::wstring* state_root, std::wstring* known_hosts_root, std::vector<BYTE>* operator_sid) {
  if (!CurrentUserSid(operator_sid)) return false;
  HKEY raw_key = nullptr;
  if (RegOpenKeyExW(HKEY_CURRENT_USER, kConfigurationKey, 0, KEY_READ | READ_CONTROL, &raw_key) != ERROR_SUCCESS) return false;
  RegistryKey key(raw_key);
  if (!VerifyRegistryConfiguration(key.get(), operator_sid->data())) return false;
  if (!ReadStringValue(key.get(), L"StateRoot", state_root) || !ReadStringValue(key.get(), L"KnownHostsRoot", known_hosts_root) || !IsLocalNtfsPath(*state_root) || !IsLocalNtfsPath(*known_hosts_root) || !RootsAreDistinct(*state_root, *known_hosts_root, operator_sid->data())) return false;
  return true;
}

bool VerifyFile(HANDLE handle, PSID operator_sid, bool directory, bool require_operator_owner = true, bool require_protected_dacl = true) {
  FILE_ATTRIBUTE_TAG_INFO tag{};
  if (!GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &tag, sizeof(tag)) || (tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) return false;
  BY_HANDLE_FILE_INFORMATION info{};
  if (!GetFileInformationByHandle(handle, &info) || ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) != directory) return false;
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  PSID owner = nullptr;
  PACL dacl = nullptr;
  const DWORD result = GetSecurityInfo(handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, nullptr, &dacl, nullptr, &descriptor);
  if (result != ERROR_SUCCESS || descriptor == nullptr || owner == nullptr) { if (descriptor != nullptr) LocalFree(descriptor); return false; }
  SECURITY_DESCRIPTOR_CONTROL control = 0;
  DWORD revision = 0;
  GENERIC_MAPPING mapping{FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS};
  const ACCESS_MASK mutation = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER;
  const bool owner_safe = !require_operator_owner || EqualSid(owner, operator_sid);
  const bool dacl_safe = GetSecurityDescriptorControl(descriptor, &control, &revision) && (!require_protected_dacl || (control & SE_DACL_PROTECTED) != 0) && IsSafeDacl(dacl, operator_sid, mapping, mutation);
  const bool safe = owner_safe && dacl_safe;
  LocalFree(descriptor);
  return safe;
}

bool VerifySystemDacl(PACL dacl) {
  if (dacl == nullptr) return false;
  ACL_SIZE_INFORMATION info{};
  if (!GetAclInformation(dacl, &info, sizeof(info), AclSizeInformation)) return false;
  GENERIC_MAPPING mapping{FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS};
  const ACCESS_MASK mutation = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER;
  for (DWORD index = 0; index < info.AceCount; ++index) {
    void* raw_ace = nullptr;
    if (!GetAce(dacl, index, &raw_ace)) return false;
    auto* header = static_cast<ACE_HEADER*>(raw_ace);
    if ((header->AceFlags & INHERIT_ONLY_ACE) != 0 || header->AceType == ACCESS_DENIED_ACE_TYPE) continue;
    if (header->AceType != ACCESS_ALLOWED_ACE_TYPE) return false;
    auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(raw_ace);
    ACCESS_MASK mask = ace->Mask;
    MapGenericMask(&mask, &mapping);
    PSID sid = reinterpret_cast<PSID>(&ace->SidStart);
    if (!IsTrustedSystemSid(sid) && (mask & mutation) != 0) return false;
  }
  return true;
}

bool VerifyTrustedSystemObject(HANDLE handle, bool directory) {
  FILE_ATTRIBUTE_TAG_INFO tag{};
  if (!GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &tag, sizeof(tag)) || (tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) return false;
  BY_HANDLE_FILE_INFORMATION info{};
  if (!GetFileInformationByHandle(handle, &info) || ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) != directory) return false;
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  PSID owner = nullptr;
  PACL dacl = nullptr;
  const DWORD result = GetSecurityInfo(handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, nullptr, &dacl, nullptr, &descriptor);
  if (result != ERROR_SUCCESS || descriptor == nullptr || owner == nullptr) { if (descriptor != nullptr) LocalFree(descriptor); return false; }
  const bool safe = IsTrustedSystemSid(owner) && VerifySystemDacl(dacl);
  LocalFree(descriptor);
  return safe;
}

bool SameIdentity(HANDLE left, HANDLE right) {
  FILE_ID_INFO first{};
  FILE_ID_INFO second{};
  return GetFileInformationByHandleEx(left, FileIdInfo, &first, sizeof(first)) && GetFileInformationByHandleEx(right, FileIdInfo, &second, sizeof(second)) && first.VolumeSerialNumber == second.VolumeSerialNumber && memcmp(first.FileId.Identifier, second.FileId.Identifier, sizeof(first.FileId.Identifier)) == 0;
}

bool VerifyDirectoryChain(const std::wstring& path, PSID operator_sid) {
  if (!IsLocalNtfsPath(path)) return false;
  size_t cursor = 3;
  while (cursor < path.size()) {
    const size_t next = path.find_first_of(L"\\/", cursor);
    const size_t length = next == std::wstring::npos ? path.size() : next;
    if (length == cursor) return false;
    const std::wstring component = path.substr(0, length);
    Handle handle(CreateFileW(component.c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    if (handle.get() == INVALID_HANDLE_VALUE || !VerifyFile(handle.get(), operator_sid, true, length == path.size(), length == path.size())) return false;
    if (next == std::wstring::npos) return true;
    cursor = next + 1;
  }
  return false;
}

bool FinalPath(HANDLE handle, std::wstring* value) {
  const DWORD required = GetFinalPathNameByHandleW(handle, nullptr, 0, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
  if (required == 0 || required > 32768) return false;
  std::vector<wchar_t> buffer(required + 1);
  if (GetFinalPathNameByHandleW(handle, buffer.data(), static_cast<DWORD>(buffer.size()), FILE_NAME_NORMALIZED | VOLUME_NAME_DOS) == 0) return false;
  value->assign(buffer.data());
  return true;
}

std::wstring StripExtendedPrefix(const std::wstring& path) {
  return path.rfind(L"\\\\?\\", 0) == 0 ? path.substr(4) : path;
}

bool HasMicrosoftPublisher(PCCERT_CONTEXT context) {
  if (context == nullptr) return false;
  static constexpr BYTE kAllowedThumbprints[][20] = {{0x66, 0x7B, 0xBA, 0x1E, 0x1F, 0x47, 0x82, 0x21, 0xAA, 0x65, 0xDE, 0x4F, 0x75, 0x18, 0x7A, 0x75, 0x1B, 0x03, 0xA4, 0x53}};
  BYTE thumbprint[20]{};
  DWORD thumbprint_size = sizeof(thumbprint);
  if (!CertGetCertificateContextProperty(context, CERT_SHA1_HASH_PROP_ID, thumbprint, &thumbprint_size) || thumbprint_size != sizeof(thumbprint)) return false;
  bool thumbprint_allowed = false;
  for (const auto& allowed : kAllowedThumbprints) {
    if (std::memcmp(thumbprint, allowed, sizeof(thumbprint)) == 0) { thumbprint_allowed = true; break; }
  }
  if (!thumbprint_allowed) return false;
  const DWORD subject_size = CertGetNameStringW(context, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, nullptr, 0);
  std::vector<wchar_t> subject(subject_size + 1);
  const bool trusted = subject_size > 1 && CertGetNameStringW(context, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, subject.data(), static_cast<DWORD>(subject.size())) != 0 && _wcsicmp(subject.data(), L"Microsoft Windows") == 0;
  return trusted;
}

bool VerifyCatalogMember(const std::wstring& path) {
  Handle file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
  if (file.get() == INVALID_HANDLE_VALUE) return false;
  HCATADMIN administrator = nullptr;
  if (!CryptCATAdminAcquireContext(&administrator, nullptr, 0)) return false;
  DWORD hash_size = 0;
  if (!CryptCATAdminCalcHashFromFileHandle(file.get(), &hash_size, nullptr, 0) || hash_size == 0) { CryptCATAdminReleaseContext(administrator, 0); return false; }
  std::vector<BYTE> hash(hash_size);
  if (!CryptCATAdminCalcHashFromFileHandle(file.get(), &hash_size, hash.data(), 0)) { CryptCATAdminReleaseContext(administrator, 0); return false; }
  static constexpr wchar_t kHex[] = L"0123456789ABCDEF";
  std::wstring tag;
  tag.reserve(hash_size * 2);
  for (DWORD index = 0; index < hash_size; ++index) { tag.push_back(kHex[(hash[index] >> 4) & 0x0f]); tag.push_back(kHex[hash[index] & 0x0f]); }
  HCATINFO previous = nullptr;
  bool trusted = false;
  while (HCATINFO catalog = CryptCATAdminEnumCatalogFromHash(administrator, hash.data(), hash_size, 0, &previous)) {
    previous = catalog;
    CATALOG_INFO info{};
    info.cbStruct = sizeof(info);
    if (!CryptCATCatalogInfoFromContext(catalog, &info, 0)) continue;
    WINTRUST_CATALOG_INFO member{};
    member.cbStruct = sizeof(member);
    member.pcwszCatalogFilePath = info.wszCatalogFile;
    member.pcwszMemberTag = tag.c_str();
    member.pcwszMemberFilePath = path.c_str();
    member.hMemberFile = file.get();
    member.pbCalculatedFileHash = hash.data();
    member.cbCalculatedFileHash = hash_size;
    member.hCatAdmin = administrator;
    WINTRUST_DATA trust_data{};
    trust_data.cbStruct = sizeof(trust_data);
    trust_data.dwUIChoice = WTD_UI_NONE;
    trust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
    trust_data.dwUnionChoice = WTD_CHOICE_CATALOG;
    trust_data.pCatalog = &member;
    trust_data.dwStateAction = WTD_STATEACTION_VERIFY;
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    const LONG status = WinVerifyTrust(nullptr, &action, &trust_data);
    bool publisher_matches = false;
    if (status == ERROR_SUCCESS) {
      CRYPT_PROVIDER_DATA* provider = WTHelperProvDataFromStateData(trust_data.hWVTStateData);
      CRYPT_PROVIDER_SGNR* signer = provider == nullptr ? nullptr : WTHelperGetProvSignerFromChain(provider, 0, FALSE, 0);
      publisher_matches = signer != nullptr && signer->csCertChain > 0 && signer->pasCertChain != nullptr && HasMicrosoftPublisher(signer->pasCertChain[0].pCert);
    }
    trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &action, &trust_data);
    if (status == ERROR_SUCCESS && publisher_matches) { trusted = true; break; }
  }
  if (previous != nullptr) CryptCATAdminReleaseCatalogContext(administrator, previous, 0);
  CryptCATAdminReleaseContext(administrator, 0);
  return trusted;
}

bool IsMicrosoftSigned(const std::wstring& path) {
  return VerifyCatalogMember(path);
}

bool IsSupportedOpenSshVersion(const std::wstring& path, std::array<DWORD, 4>* version) {
  DWORD unused = 0;
  const DWORD bytes = GetFileVersionInfoSizeW(path.c_str(), &unused);
  if (bytes == 0 || bytes > 1024 * 1024) return false;
  std::vector<BYTE> data(bytes);
  if (!GetFileVersionInfoW(path.c_str(), 0, bytes, data.data())) return false;
  VS_FIXEDFILEINFO* info = nullptr;
  UINT info_bytes = 0;
  if (!VerQueryValueW(data.data(), L"\\", reinterpret_cast<void**>(&info), &info_bytes) || info == nullptr || info_bytes < sizeof(VS_FIXEDFILEINFO) || info->dwSignature != 0xfeef04bd) return false;
  *version = {HIWORD(info->dwFileVersionMS), LOWORD(info->dwFileVersionMS), HIWORD(info->dwFileVersionLS), LOWORD(info->dwFileVersionLS)};
  return (*version)[0] > 9 || ((*version)[0] == 9 && (*version)[1] >= 5);
}

bool OpenTrustedSystemObject(const std::wstring& path, bool directory, Handle* result) {
  const DWORD flags = (directory ? FILE_FLAG_BACKUP_SEMANTICS : 0) | FILE_FLAG_OPEN_REPARSE_POINT;
  Handle handle(CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL, FILE_SHARE_READ, nullptr, OPEN_EXISTING, flags, nullptr));
  if (handle.get() == INVALID_HANDLE_VALUE || !VerifyTrustedSystemObject(handle.get(), directory)) return false;
  std::wstring final_path;
  if (!FinalPath(handle.get(), &final_path) || _wcsicmp(StripExtendedPrefix(final_path).c_str(), path.c_str()) != 0) return false;
  *result = std::move(handle);
  return true;
}

bool SystemDirectory(std::wstring* value) {
#ifdef SSH_MCP_NATIVE_TEST
  if (g_test_system_directory != nullptr) {
    *value = *g_test_system_directory;
    return IsAbsoluteLocalPath(*value) && IsLocalNtfsPath(*value);
  }
#endif
  std::vector<wchar_t> buffer(MAX_PATH);
  const UINT required = GetSystemDirectoryW(buffer.data(), static_cast<UINT>(buffer.size()));
  if (required == 0 || required >= 32768) return false;
  if (required >= buffer.size()) {
    buffer.resize(required + 1);
    if (GetSystemDirectoryW(buffer.data(), static_cast<UINT>(buffer.size())) == 0) return false;
  }
  value->assign(buffer.data());
  return IsAbsoluteLocalPath(*value) && IsLocalNtfsPath(*value);
}

bool IsExpectedOpenSshExecutable(const std::wstring& path) {
  std::wstring system;
  if (!SystemDirectory(&system)) return false;
  const std::wstring directory = system + L"\\OpenSSH";
  return _wcsicmp(path.c_str(), (directory + L"\\ssh.exe").c_str()) == 0 || _wcsicmp(path.c_str(), (directory + L"\\ssh-add.exe").c_str()) == 0;
}

bool TrustedOpenSsh(std::wstring* ssh, std::wstring* ssh_add, std::array<DWORD, 4>* version, Handle* retained_system = nullptr, Handle* retained_directory = nullptr, Handle* retained_ssh_add = nullptr, Handle* retained_ssh = nullptr) {
  std::wstring system;
  if (!SystemDirectory(&system)) return false;
  const std::wstring directory = system + L"\\OpenSSH";
  *ssh = directory + L"\\ssh.exe";
  *ssh_add = directory + L"\\ssh-add.exe";
  Handle system_handle;
  Handle openssh_handle;
  Handle ssh_handle;
  Handle ssh_add_handle;
  const bool trusted = IsExpectedOpenSshExecutable(*ssh) && IsExpectedOpenSshExecutable(*ssh_add) && OpenTrustedSystemObject(system, true, &system_handle) && OpenTrustedSystemObject(directory, true, &openssh_handle) && OpenTrustedSystemObject(*ssh, false, &ssh_handle) && OpenTrustedSystemObject(*ssh_add, false, &ssh_add_handle) && IsMicrosoftSigned(*ssh) && IsMicrosoftSigned(*ssh_add) && IsSupportedOpenSshVersion(*ssh, version) && IsSupportedOpenSshVersion(*ssh_add, version);
  if (trusted) {
    if (retained_system != nullptr) *retained_system = std::move(system_handle);
    if (retained_directory != nullptr) *retained_directory = std::move(openssh_handle);
    if (retained_ssh_add != nullptr) *retained_ssh_add = std::move(ssh_add_handle);
    if (retained_ssh != nullptr) *retained_ssh = std::move(ssh_handle);
  }
  return trusted;
}

bool RootsAreDistinct(const std::wstring& state_root, const std::wstring& known_hosts_root, PSID operator_sid) {
  if (!VerifyDirectoryChain(state_root, operator_sid) || !VerifyDirectoryChain(known_hosts_root, operator_sid)) return false;
  Handle state(CreateFileW(state_root.c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
  Handle known_hosts(CreateFileW(known_hosts_root.c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
  if (state.get() == INVALID_HANDLE_VALUE || known_hosts.get() == INVALID_HANDLE_VALUE || !VerifyFile(state.get(), operator_sid, true) || !VerifyFile(known_hosts.get(), operator_sid, true) || SameIdentity(state.get(), known_hosts.get())) return false;
  std::wstring state_final;
  std::wstring known_hosts_final;
  return FinalPath(state.get(), &state_final) && FinalPath(known_hosts.get(), &known_hosts_final) && !IsSameOrNestedPath(state_final, known_hosts_final) && !IsSameOrNestedPath(known_hosts_final, state_final);
}

bool ReadProtectedFile(const std::wstring& root, const std::wstring& leaf, PSID operator_sid, std::vector<BYTE>* output) {
  if (leaf.empty() || leaf.find_first_of(L"\\/:*") != std::wstring::npos) return false;
  if (!VerifyDirectoryChain(root, operator_sid)) return false;
  DWORD initial_share = FILE_SHARE_READ;
#ifdef SSH_MCP_NATIVE_TEST
  if (g_test_protected_file_pre_recheck != nullptr) initial_share |= FILE_SHARE_WRITE | FILE_SHARE_DELETE;
#endif
  Handle root_handle(CreateFileW(root.c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL, initial_share, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
  if (root_handle.get() == INVALID_HANDLE_VALUE || !VerifyFile(root_handle.get(), operator_sid, true)) return false;
  const std::wstring path = root + L"\\" + leaf;
  Handle file_handle(CreateFileW(path.c_str(), GENERIC_READ | FILE_READ_ATTRIBUTES | READ_CONTROL, initial_share, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
  if (file_handle.get() == INVALID_HANDLE_VALUE || !VerifyFile(file_handle.get(), operator_sid, false)) return false;
#ifdef SSH_MCP_NATIVE_TEST
  if (g_test_protected_file_pre_recheck != nullptr && !g_test_protected_file_pre_recheck()) return false;
#endif
  Handle root_recheck(CreateFileW(root.c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
  Handle file_recheck(CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
  if (root_recheck.get() == INVALID_HANDLE_VALUE || file_recheck.get() == INVALID_HANDLE_VALUE || !VerifyDirectoryChain(root, operator_sid) || !VerifyFile(root_recheck.get(), operator_sid, true) || !VerifyFile(file_recheck.get(), operator_sid, false) || !SameIdentity(root_handle.get(), root_recheck.get()) || !SameIdentity(file_handle.get(), file_recheck.get())) return false;
  std::wstring root_final;
  std::wstring file_final;
  if (!FinalPath(root_handle.get(), &root_final) || !FinalPath(file_handle.get(), &file_final) || file_final.size() <= root_final.size() + 1 || _wcsnicmp(file_final.c_str(), root_final.c_str(), root_final.size()) != 0 || file_final[root_final.size()] != L'\\' || file_final.find(L'\\', root_final.size() + 1) != std::wstring::npos) return false;
  LARGE_INTEGER size{};
  if (!GetFileSizeEx(file_handle.get(), &size) || size.QuadPart <= 0 || size.QuadPart > kMaxFileBytes) return false;
  output->resize(static_cast<size_t>(size.QuadPart));
  DWORD bytes_read = 0;
  if (!ReadFile(file_handle.get(), output->data(), static_cast<DWORD>(output->size()), &bytes_read, nullptr) || bytes_read != output->size()) return false;
  return true;
}

class PrivateSecurityAttributes final {
 public:
  explicit PrivateSecurityAttributes(PSID operator_sid) {
    if (operator_sid != nullptr) acl_.resize(sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD) + GetLengthSid(operator_sid));
    valid_ = operator_sid != nullptr && InitializeAcl(reinterpret_cast<PACL>(acl_.data()), static_cast<DWORD>(acl_.size()), ACL_REVISION) && AddAccessAllowedAceEx(reinterpret_cast<PACL>(acl_.data()), ACL_REVISION, OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE, FILE_ALL_ACCESS, operator_sid) && InitializeSecurityDescriptor(&descriptor_, SECURITY_DESCRIPTOR_REVISION) && SetSecurityDescriptorOwner(&descriptor_, operator_sid, FALSE) && SetSecurityDescriptorDacl(&descriptor_, TRUE, reinterpret_cast<PACL>(acl_.data()), FALSE) && SetSecurityDescriptorControl(&descriptor_, SE_DACL_PROTECTED, SE_DACL_PROTECTED);
    attributes_.nLength = sizeof(attributes_);
    attributes_.lpSecurityDescriptor = valid_ ? &descriptor_ : nullptr;
    attributes_.bInheritHandle = FALSE;
  }

  bool valid() const { return valid_; }
  SECURITY_ATTRIBUTES* get() { return &attributes_; }
  PSECURITY_DESCRIPTOR descriptor() { return valid_ ? &descriptor_ : nullptr; }

 private:
  SECURITY_DESCRIPTOR descriptor_{};
  std::vector<BYTE> acl_;
  SECURITY_ATTRIBUTES attributes_{};
  bool valid_ = false;
};

bool ReadIdentity(HANDLE handle, FILE_ID_INFO* identity) {
  return GetFileInformationByHandleEx(handle, FileIdInfo, identity, sizeof(*identity)) != 0;
}

bool HasIdentity(HANDLE handle, const FILE_ID_INFO& expected) {
  FILE_ID_INFO current{};
  return ReadIdentity(handle, &current) && current.VolumeSerialNumber == expected.VolumeSerialNumber && memcmp(current.FileId.Identifier, expected.FileId.Identifier, sizeof(current.FileId.Identifier)) == 0;
}

#ifdef SSH_MCP_NATIVE_TEST
constexpr napi_type_tag kSnapshotCapabilityTypeTag{0x13a5c33f91d1b7e4ULL, 0x7e4bd2191c098aa3ULL};
#else
constexpr napi_type_tag kSnapshotCapabilityTypeTag{0xb1c7a8d93ef01642ULL, 0x2e6f4175ca903bd8ULL};
#endif

enum class SnapshotFailure {
  kNone,
  kDirectoryCreate,
  kDirectoryVerify,
  kDirectoryIdentity,
  kFileVerify,
  kFileIdentity,
  kWrite,
  kFlush,
  kFileDisposition,
  kDirectoryDisposition,
};

#ifdef SSH_MCP_NATIVE_TEST
SnapshotFailure g_test_snapshot_failure = SnapshotFailure::kNone;
DWORD g_test_snapshot_fresh_identity_rechecks = 0;

bool ConsumeSnapshotFailure(SnapshotFailure failure) {
  if (g_test_snapshot_failure != failure) return false;
  g_test_snapshot_failure = SnapshotFailure::kNone;
  return true;
}
#else
bool ConsumeSnapshotFailure(SnapshotFailure) { return false; }
#endif

using NativeCreateFile = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);

NativeCreateFile GetNativeCreateFile() {
  static const auto create = reinterpret_cast<NativeCreateFile>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateFile"));
  return create;
}

bool CreatePrivateRelative(HANDLE root, const std::wstring& leaf, PrivateSecurityAttributes& security, bool directory, SnapshotFailure failure, Handle* result) {
  if (root == INVALID_HANDLE_VALUE || leaf.empty() || leaf.size() > USHRT_MAX / sizeof(wchar_t) || leaf.find_first_of(L"\\/") != std::wstring::npos) return false;
  if (ConsumeSnapshotFailure(failure)) return false;
  NativeCreateFile create = GetNativeCreateFile();
  if (create == nullptr) return false;
  UNICODE_STRING name{};
  name.Buffer = const_cast<wchar_t*>(leaf.data());
  name.Length = static_cast<USHORT>(leaf.size() * sizeof(wchar_t));
  name.MaximumLength = name.Length;
  OBJECT_ATTRIBUTES attributes{};
  InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE, root, security.descriptor());
  IO_STATUS_BLOCK status{};
  HANDLE raw = INVALID_HANDLE_VALUE;
  const ACCESS_MASK access = directory ? FILE_READ_ATTRIBUTES | READ_CONTROL | DELETE | SYNCHRONIZE : GENERIC_READ | GENERIC_WRITE | FILE_READ_ATTRIBUTES | READ_CONTROL | DELETE | SYNCHRONIZE;
  const ULONG options = (directory ? FILE_DIRECTORY_FILE : FILE_NON_DIRECTORY_FILE) | FILE_SYNCHRONOUS_IO_NONALERT;
  // Retain read-only sharing: OpenSSH can read the snapshot, while write,
  // delete, and replacement opens remain blocked until disposal.
  if (create(&raw, access, &attributes, &status, nullptr, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_CREATE, options, nullptr, 0) < 0 || raw == INVALID_HANDLE_VALUE) return false;
  *result = Handle(raw);
  return true;
}

class SnapshotSession final {
 public:
  explicit SnapshotSession(PSID operator_sid)
      : operator_sid_(static_cast<const BYTE*>(operator_sid), static_cast<const BYTE*>(operator_sid) + GetLengthSid(operator_sid)), capability_tag_(&kSnapshotCapabilityTypeTag) {}
  ~SnapshotSession() {
    if (!disposed_) {
      Rollback();
      // A finalizer has no remaining JavaScript capability to drive a later
      // retry. Retry once for transient failures, then fail closed by closing
      // only the retained handles without following a pathname.
      if (HasArtifacts()) Rollback();
    }
  }
  SnapshotSession(const SnapshotSession&) = delete;
  SnapshotSession& operator=(const SnapshotSession&) = delete;

  bool AdoptParent(Handle parent) {
    parent_ = std::move(parent);
    parent_identity_known_ = ReadIdentity(parent_.get(), &parent_identity_);
    return parent_identity_known_;
  }

  bool AdoptDirectory(Handle directory) {
    directory_ = std::move(directory);
    directory_fresh_ = true;
    directory_identity_known_ = !ConsumeSnapshotFailure(SnapshotFailure::kDirectoryIdentity) && ReadIdentity(directory_.get(), &directory_identity_);
    return directory_identity_known_;
  }

  bool AdoptFile(Handle file) {
    file_ = std::move(file);
    file_fresh_ = true;
    file_identity_known_ = !ConsumeSnapshotFailure(SnapshotFailure::kFileIdentity) && ReadIdentity(file_.get(), &file_identity_);
    return file_identity_known_;
  }

  bool VerifyDirectory(PSID operator_sid) const { return VerifyFile(directory_.get(), operator_sid, true); }
  bool VerifySnapshotFile(PSID operator_sid) const { return VerifyFile(file_.get(), operator_sid, false); }

  bool Write(const std::vector<BYTE>& data) {
    if (ConsumeSnapshotFailure(SnapshotFailure::kWrite)) return false;
    DWORD bytes_written = 0;
    return WriteFile(file_.get(), data.data(), static_cast<DWORD>(data.size()), &bytes_written, nullptr) && bytes_written == data.size() && !ConsumeSnapshotFailure(SnapshotFailure::kFlush) && FlushFileBuffers(file_.get());
  }

  HANDLE parent_handle() const { return parent_.get(); }
  HANDLE directory_handle() const { return directory_.get(); }
  bool IsReady() const { return parent_identity_known_ && directory_identity_known_ && file_identity_known_ && parent_.get() != INVALID_HANDLE_VALUE && directory_.get() != INVALID_HANDLE_VALUE && file_.get() != INVALID_HANDLE_VALUE; }
  bool IsValidCapability() const { return !disposed_ && parent_.get() != INVALID_HANDLE_VALUE && directory_.get() != INVALID_HANDLE_VALUE && capability_tag_ == &kSnapshotCapabilityTypeTag; }

  bool ReadyKnownHostsPath(std::wstring* path, std::wstring* directory) const {
    if (!IsValidCapability() || !parent_identity_known_ || !directory_identity_known_ || !file_identity_known_ ||
        !HasIdentity(parent_.get(), parent_identity_) || !HasIdentity(directory_.get(), directory_identity_) ||
        !HasIdentity(file_.get(), file_identity_) || !VerifyFile(parent_.get(), operator_sid(), true) ||
        !VerifyFile(directory_.get(), operator_sid(), true) || !VerifyFile(file_.get(), operator_sid(), false))
      return false;
    std::wstring final_directory;
    std::wstring final_file;
    if (!FinalPath(directory_.get(), &final_directory) || !FinalPath(file_.get(), &final_file)) return false;
    final_directory = StripExtendedPrefix(final_directory);
    final_file = StripExtendedPrefix(final_file);
    if (_wcsicmp(final_file.c_str(), (final_directory + L"\\known_hosts").c_str()) != 0) return false;
    *directory = std::move(final_directory);
    *path = std::move(final_file);
    return true;
  }

  bool Dispose() {
    if (disposed_) return false;
    if (!Rollback() || HasArtifacts()) return false;
    disposed_ = true;
    return true;
  }

 private:
  bool HasArtifacts() const { return directory_.get() != INVALID_HANDLE_VALUE || file_.get() != INVALID_HANDLE_VALUE; }

  bool Rollback() {
    if (file_.get() != INVALID_HANDLE_VALUE) {
      const bool file_verified = file_identity_known_ ? HasIdentity(file_.get(), file_identity_) && VerifyFile(file_.get(), operator_sid(), false) : RevalidateFreshFile();
      if (!file_verified || ConsumeSnapshotFailure(SnapshotFailure::kFileDisposition)) return false;
      FILE_DISPOSITION_INFO delete_info{};
      delete_info.DeleteFile = TRUE;
      if (!SetFileInformationByHandle(file_.get(), FileDispositionInfo, &delete_info, sizeof(delete_info))) return false;
      file_.reset();
    }
    if (directory_.get() != INVALID_HANDLE_VALUE) {
      const bool directory_verified = directory_identity_known_ ? parent_identity_known_ && HasIdentity(parent_.get(), parent_identity_) && HasIdentity(directory_.get(), directory_identity_) && VerifyFile(parent_.get(), operator_sid(), true) && VerifyFile(directory_.get(), operator_sid(), true) : RevalidateFreshDirectory();
      if (!directory_verified || ConsumeSnapshotFailure(SnapshotFailure::kDirectoryDisposition)) return false;
      FILE_DISPOSITION_INFO delete_info{};
      delete_info.DeleteFile = TRUE;
      if (!SetFileInformationByHandle(directory_.get(), FileDispositionInfo, &delete_info, sizeof(delete_info))) return false;
      directory_.reset();
    }
    parent_.reset();
    return true;
  }

  bool RevalidateFreshFile() {
#ifdef SSH_MCP_NATIVE_TEST
    ++g_test_snapshot_fresh_identity_rechecks;
#endif
    if (!file_fresh_ || !ReadIdentity(file_.get(), &file_identity_) || !VerifyFile(file_.get(), operator_sid(), false)) return false;
    file_identity_known_ = true;
    return true;
  }

  bool RevalidateFreshDirectory() {
#ifdef SSH_MCP_NATIVE_TEST
    ++g_test_snapshot_fresh_identity_rechecks;
#endif
    if (!directory_fresh_ || !parent_identity_known_ || !HasIdentity(parent_.get(), parent_identity_) || !VerifyFile(parent_.get(), operator_sid(), true) || !ReadIdentity(directory_.get(), &directory_identity_) || !VerifyFile(directory_.get(), operator_sid(), true)) return false;
    directory_identity_known_ = true;
    return true;
  }

  PSID operator_sid() const { return static_cast<PSID>(const_cast<BYTE*>(operator_sid_.data())); }

  std::vector<BYTE> operator_sid_;
  const void* capability_tag_;
  Handle parent_;
  Handle directory_;
  Handle file_;
  FILE_ID_INFO parent_identity_{};
  FILE_ID_INFO directory_identity_{};
  FILE_ID_INFO file_identity_{};
  bool parent_identity_known_ = false;
  bool directory_identity_known_ = false;
  bool file_identity_known_ = false;
  bool directory_fresh_ = false;
  bool file_fresh_ = false;
  bool disposed_ = false;
};

LONG g_snapshot_counter = 0;

bool CreateKnownHostsSnapshot(const std::wstring& state_root, PSID operator_sid, const std::vector<BYTE>& data, std::unique_ptr<SnapshotSession>* snapshot) {
  if (data.empty() || data.size() > kMaxFileBytes || !VerifyDirectoryChain(state_root, operator_sid)) return false;
  Handle parent(CreateFileW(state_root.c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL | FILE_ADD_SUBDIRECTORY | FILE_TRAVERSE, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
  if (parent.get() == INVALID_HANDLE_VALUE || !VerifyFile(parent.get(), operator_sid, true)) return false;
  PrivateSecurityAttributes security(operator_sid);
  if (!security.valid()) return false;
  std::unique_ptr<SnapshotSession> candidate(new SnapshotSession(operator_sid));
  if (!candidate->AdoptParent(std::move(parent))) return false;
  for (DWORD attempt = 0; attempt != 16; ++attempt) {
    unsigned int random_value = 0;
    if (BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(&random_value), sizeof(random_value), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) return false;
    const std::wstring name = L".ssh-mcp-snapshot-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64()) + L"-" + std::to_wstring(InterlockedIncrement(&g_snapshot_counter)) + L"-" + std::to_wstring(random_value);
    Handle directory;
    if (!CreatePrivateRelative(candidate->parent_handle(), name, security, true, SnapshotFailure::kDirectoryCreate, &directory)) return false;
    if (!candidate->AdoptDirectory(std::move(directory)) || ConsumeSnapshotFailure(SnapshotFailure::kDirectoryVerify) || !candidate->VerifyDirectory(operator_sid)) return false;
    Handle file;
    if (!CreatePrivateRelative(candidate->directory_handle(), L"known_hosts", security, false, SnapshotFailure::kNone, &file)) return false;
    if (file.get() == INVALID_HANDLE_VALUE || !candidate->AdoptFile(std::move(file)) || ConsumeSnapshotFailure(SnapshotFailure::kFileVerify) || !candidate->VerifySnapshotFile(operator_sid)) return false;
    if (!candidate->Write(data)) return false;
    if (!candidate->IsReady()) return false;
    *snapshot = std::move(candidate);
    return true;
  }
  return false;
}

void FinalizeSnapshotCapability(napi_env, void* data, void*) {
  delete static_cast<SnapshotSession*>(data);
}

enum class LaunchResult { kCompleted, kTimedOut, kFailed };

LaunchResult LaunchHiddenProcess(const std::wstring& application, std::wstring command, DWORD timeout, DWORD* exit_code) {
  SECURITY_ATTRIBUTES inheritable{};
  inheritable.nLength = sizeof(inheritable);
  inheritable.bInheritHandle = TRUE;
  Handle nul(CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &inheritable, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
  if (nul.get() == INVALID_HANDLE_VALUE) return LaunchResult::kFailed;
  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESTDHANDLES;
  startup.hStdInput = nul.get();
  startup.hStdOutput = nul.get();
  startup.hStdError = nul.get();
  PROCESS_INFORMATION process{};
  if (!CreateProcessW(application.c_str(), command.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process)) return LaunchResult::kFailed;
  Handle process_handle(process.hProcess);
  Handle thread_handle(process.hThread);
  const DWORD wait = WaitForSingleObject(process_handle.get(), timeout);
  if (wait == WAIT_TIMEOUT) {
    if (!TerminateProcess(process_handle.get(), 1) || WaitForSingleObject(process_handle.get(), INFINITE) != WAIT_OBJECT_0) return LaunchResult::kFailed;
    return LaunchResult::kTimedOut;
  }
  if (wait != WAIT_OBJECT_0 || !GetExitCodeProcess(process_handle.get(), exit_code)) return LaunchResult::kFailed;
  return LaunchResult::kCompleted;
}

LaunchResult ProbeTrustedOpenSsh(DWORD timeout, DWORD* exit_code) {
  std::wstring ssh;
  std::wstring ssh_add;
  std::array<DWORD, 4> version{};
  Handle system_handle;
  Handle openssh_handle;
  Handle ssh_add_handle;
  if (!TrustedOpenSsh(&ssh, &ssh_add, &version, &system_handle, &openssh_handle, &ssh_add_handle)) return LaunchResult::kFailed;
#ifdef SSH_MCP_NATIVE_TEST
  if (g_test_openssh_pre_launch != nullptr && !g_test_openssh_pre_launch(ssh_add)) return LaunchResult::kFailed;
#endif
  std::wstring command = L"\"" + ssh_add + L"\" -l";
  return LaunchHiddenProcess(ssh_add, std::move(command), timeout, exit_code);
}

bool StartHiddenProcess(const std::wstring& application, std::wstring command, Handle* process_handle) {
  SECURITY_ATTRIBUTES inheritable{};
  inheritable.nLength = sizeof(inheritable);
  inheritable.bInheritHandle = TRUE;
  Handle nul(CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &inheritable, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
  if (nul.get() == INVALID_HANDLE_VALUE) return false;
  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESTDHANDLES;
  startup.hStdInput = nul.get();
  startup.hStdOutput = nul.get();
  startup.hStdError = nul.get();
  PROCESS_INFORMATION process{};
  if (!CreateProcessW(application.c_str(), command.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process)) return false;
  CloseHandle(process.hThread);
  *process_handle = Handle(process.hProcess);
  return true;
}

void AppendQuotedArgument(std::wstring* command, const std::wstring& argument) {
  command->push_back(L' ');
  command->push_back(L'"');
  size_t slashes = 0;
  for (wchar_t character : argument) {
    if (character == L'\\') {
      ++slashes;
      continue;
    }
    if (character == L'"') command->append(slashes * 2 + 1, L'\\');
    else command->append(slashes, L'\\');
    slashes = 0;
    command->push_back(character);
  }
  command->append(slashes * 2, L'\\');
  command->push_back(L'"');
}

std::wstring FixedCommandLine(const std::wstring& application, const std::vector<std::wstring>& arguments) {
  std::wstring command;
  AppendQuotedArgument(&command, application);
  for (const auto& argument : arguments) AppendQuotedArgument(&command, argument);
  return command;
}

bool IsSafeReadinessHost(const std::wstring& host) {
  if (host.empty() || host.size() > 253 || host.front() == L'-' || host.back() == L'.') return false;
  for (wchar_t character : host) {
    if (!((character >= L'a' && character <= L'z') || (character >= L'A' && character <= L'Z') || (character >= L'0' && character <= L'9') || character == L'.' || character == L'-' || character == L':' || character == L'%')) return false;
  }
  return true;
}

bool IsSafeReadinessUser(const std::wstring& user) {
  if (user.empty() || user.size() > 64 || user.front() == L'-') return false;
  for (wchar_t character : user) {
    if (!((character >= L'a' && character <= L'z') || (character >= L'A' && character <= L'Z') || (character >= L'0' && character <= L'9') || character == L'.' || character == L'_' || character == L'-')) return false;
  }
  return true;
}

bool ReadUtf16Property(napi_env env, napi_value object, const char* name, std::wstring* value) {
  napi_value property{};
  size_t length = 0;
  if (napi_get_named_property(env, object, name, &property) != napi_ok || napi_get_value_string_utf16(env, property, nullptr, 0, &length) != napi_ok || length == 0 || length > 253) return false;
  std::vector<char16_t> buffer(length + 1);
  if (napi_get_value_string_utf16(env, property, buffer.data(), buffer.size(), &length) != napi_ok) return false;
  value->assign(reinterpret_cast<const wchar_t*>(buffer.data()), length);
  return value->find(L'\0') == std::wstring::npos;
}

bool ReadReadinessDescriptor(napi_env env, napi_value descriptor, std::wstring* host, DWORD* port, std::wstring* user) {
  napi_valuetype type{};
  napi_value names{};
  uint32_t length = 0;
  if (napi_typeof(env, descriptor, &type) != napi_ok || type != napi_object || napi_get_property_names(env, descriptor, &names) != napi_ok || napi_get_array_length(env, names, &length) != napi_ok || length != 3) return false;
  bool has_host = false;
  bool has_port = false;
  bool has_user = false;
  for (uint32_t index = 0; index < length; ++index) {
    napi_value name{};
    size_t name_length = 0;
    if (napi_get_element(env, names, index, &name) != napi_ok || napi_get_value_string_utf8(env, name, nullptr, 0, &name_length) != napi_ok) return false;
    std::vector<char> key(name_length + 1);
    if (napi_get_value_string_utf8(env, name, key.data(), key.size(), &name_length) != napi_ok) return false;
    if (strcmp(key.data(), "host") == 0) has_host = true;
    else if (strcmp(key.data(), "port") == 0) has_port = true;
    else if (strcmp(key.data(), "user") == 0) has_user = true;
    else return false;
  }
  napi_value port_value{};
  double port_number = 0;
  if (!has_host || !has_port || !has_user || !ReadUtf16Property(env, descriptor, "host", host) || !ReadUtf16Property(env, descriptor, "user", user) || !IsSafeReadinessHost(*host) || !IsSafeReadinessUser(*user) || napi_get_named_property(env, descriptor, "port", &port_value) != napi_ok || napi_get_value_double(env, port_value, &port_number) != napi_ok || !std::isfinite(port_number) || std::floor(port_number) != port_number || port_number < 1 || port_number > 65535) return false;
  *port = static_cast<DWORD>(port_number);
  return true;
}

bool StopMaster(Handle* master, const std::wstring& ssh, const std::wstring& control_path, const std::wstring& destination, DWORD timeout) {
  DWORD ignored = 1;
  const std::vector<std::wstring> exit_arguments = {L"-F", L"none", L"-S", control_path, L"-O", L"exit", L"--", destination};
  if (timeout > 0) LaunchHiddenProcess(ssh, FixedCommandLine(ssh, exit_arguments), timeout, &ignored);
  DWORD wait = WaitForSingleObject(master->get(), timeout);
  if (wait == WAIT_OBJECT_0) return true;
  if (master->get() == INVALID_HANDLE_VALUE || !TerminateProcess(master->get(), 1)) return false;
  return WaitForSingleObject(master->get(), 1'000) == WAIT_OBJECT_0;
}

bool ValidateAgentKeyReadiness(SnapshotSession* snapshot, const std::wstring& host, DWORD port, const std::wstring& user, DWORD timeout) {
  std::wstring known_hosts;
  std::wstring snapshot_directory;
  std::wstring ssh;
  std::wstring ssh_add;
  std::array<DWORD, 4> version{};
  Handle system_handle;
  Handle openssh_handle;
  Handle ssh_add_handle;
  Handle ssh_handle;
  if (!snapshot->ReadyKnownHostsPath(&known_hosts, &snapshot_directory) || !TrustedOpenSsh(&ssh, &ssh_add, &version, &system_handle, &openssh_handle, &ssh_add_handle, &ssh_handle)) return false;
  const std::wstring control_path = snapshot_directory + L"\\control";
  const std::wstring destination = user + L"@" + host;
  const std::vector<std::wstring> master_arguments = {
      L"-F", L"none", L"-N", L"-T", L"-n", L"-M", L"-S", control_path,
      L"-o", L"ControlPersist=no", L"-o", L"CanonicalizeHostname=no", L"-o", L"ProxyCommand=none", L"-o", L"ProxyJump=none",
      L"-o", L"HostName=" + host, L"-o", L"BatchMode=yes", L"-o", L"StrictHostKeyChecking=yes", L"-o", L"UserKnownHostsFile=" + known_hosts,
      L"-o", L"GlobalKnownHostsFile=NUL", L"-o", L"PasswordAuthentication=no", L"-o", L"KbdInteractiveAuthentication=no",
      L"-o", L"NumberOfPasswordPrompts=0", L"-o", L"IdentitiesOnly=yes", L"-p", std::to_wstring(port), L"--", destination};
  Handle master;
  if (!StartHiddenProcess(ssh, FixedCommandLine(ssh, master_arguments), &master)) return false;
  const ULONGLONG started = GetTickCount64();
  bool ready = false;
  while (GetTickCount64() - started < timeout) {
    DWORD master_exit = STILL_ACTIVE;
    if (!GetExitCodeProcess(master.get(), &master_exit) || master_exit != STILL_ACTIVE) break;
    const DWORD remaining = static_cast<DWORD>(timeout - (GetTickCount64() - started));
    DWORD check_exit = 1;
    const std::vector<std::wstring> check_arguments = {L"-F", L"none", L"-S", control_path, L"-O", L"check", L"--", destination};
    if (LaunchHiddenProcess(ssh, FixedCommandLine(ssh, check_arguments), std::max<DWORD>(1, std::min<DWORD>(remaining, 250)), &check_exit) == LaunchResult::kCompleted && check_exit == 0) {
      ready = true;
      break;
    }
  }
  const ULONGLONG elapsed = GetTickCount64() - started;
  const DWORD cleanup = elapsed < timeout ? static_cast<DWORD>(timeout - elapsed) : 0;
  return StopMaster(&master, ssh, control_path, destination, cleanup) && ready;
}

bool ReadArgumentString(napi_env env, napi_callback_info info, std::string* value) {
  size_t count = 1;
  napi_value argument{};
  if (napi_get_cb_info(env, info, &count, &argument, nullptr, nullptr) != napi_ok || count != 1) return false;
  size_t bytes = 0;
  if (napi_get_value_string_utf8(env, argument, nullptr, 0, &bytes) != napi_ok || bytes == 0 || bytes > 128) return false;
  std::vector<char> buffer(bytes + 1);
  if (napi_get_value_string_utf8(env, argument, buffer.data(), buffer.size(), &bytes) != napi_ok) return false;
  value->assign(buffer.data(), bytes);
  for (char ch : *value) if (!(ch == '-' || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9'))) return false;
  return true;
}

bool ReadCredentialLocator(napi_env env, napi_callback_info info, std::string* value) {
  size_t count = 1;
  napi_value argument{};
  if (napi_get_cb_info(env, info, &count, &argument, nullptr, nullptr) != napi_ok || count != 1) return false;
  size_t bytes = 0;
  if (napi_get_value_string_utf8(env, argument, nullptr, 0, &bytes) != napi_ok || bytes == 0 || bytes > 128) return false;
  std::vector<char> buffer(bytes + 1);
  if (napi_get_value_string_utf8(env, argument, buffer.data(), buffer.size(), &bytes) != napi_ok || buffer[0] < 'a' || buffer[0] > 'z') return false;
  value->assign(buffer.data(), bytes);
  for (char ch : *value) if (!(ch == '-' || ch == '.' || ch == '_' || ch == ':' || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9'))) return false;
  return true;
}

napi_value ToBuffer(napi_env env, const std::vector<BYTE>& data) {
  void* target = nullptr;
  napi_value result{};
  if (napi_create_buffer_copy(env, data.size(), data.data(), &target, &result) != napi_ok) return Unavailable(env);
  return result;
}

napi_value ReadProfileState(napi_env env, napi_callback_info) {
  std::wstring state_root;
  std::wstring known_hosts_root;
  std::vector<BYTE> operator_sid;
  std::vector<BYTE> data;
  if (!LoadConfiguration(&state_root, &known_hosts_root, &operator_sid) || !ReadProtectedFile(state_root, kStateFile, operator_sid.data(), &data)) return Unavailable(env);
  return ToBuffer(env, data);
}

napi_value ReadKnownHosts(napi_env env, napi_callback_info info) {
  std::string profile_id;
  std::wstring state_root;
  std::wstring known_hosts_root;
  std::vector<BYTE> operator_sid;
  std::vector<BYTE> data;
  if (!ReadArgumentString(env, info, &profile_id) || !LoadConfiguration(&state_root, &known_hosts_root, &operator_sid)) return Unavailable(env);
  std::wstring leaf(profile_id.begin(), profile_id.end());
  leaf += L".known_hosts";
  if (!ReadProtectedFile(known_hosts_root, leaf, operator_sid.data(), &data)) return Unavailable(env);
  return ToBuffer(env, data);
}

napi_value CaptureKnownHostsSnapshot(napi_env env, napi_callback_info info) {
  std::string profile_id;
  std::wstring state_root;
  std::wstring known_hosts_root;
  std::vector<BYTE> operator_sid;
  std::vector<BYTE> data;
  std::unique_ptr<SnapshotSession> snapshot;
  if (!ReadArgumentString(env, info, &profile_id) || !LoadConfiguration(&state_root, &known_hosts_root, &operator_sid)) return Unavailable(env);
  std::wstring leaf(profile_id.begin(), profile_id.end());
  leaf += L".known_hosts";
  if (!ReadProtectedFile(known_hosts_root, leaf, operator_sid.data(), &data) || !CreateKnownHostsSnapshot(state_root, operator_sid.data(), data, &snapshot)) return Unavailable(env);

  napi_value result{};
  napi_value bytes{};
  napi_value capability{};
  void* bytes_copy = nullptr;
  if (napi_create_object(env, &result) != napi_ok || napi_create_buffer_copy(env, data.size(), data.data(), &bytes_copy, &bytes) != napi_ok || napi_create_object(env, &capability) != napi_ok) return Unavailable(env);
  SnapshotSession* raw_snapshot = snapshot.release();
  if (napi_wrap(env, capability, raw_snapshot, FinalizeSnapshotCapability, nullptr, nullptr) != napi_ok) {
    delete raw_snapshot;
    return Unavailable(env);
  }
  if (napi_type_tag_object(env, capability, &kSnapshotCapabilityTypeTag) != napi_ok) {
    void* unwrapped = nullptr;
    if (napi_remove_wrap(env, capability, &unwrapped) == napi_ok && unwrapped == raw_snapshot) delete raw_snapshot;
    else raw_snapshot->Dispose();
    return Unavailable(env);
  }
  if (napi_set_named_property(env, result, "bytes", bytes) != napi_ok || napi_set_named_property(env, result, "capability", capability) != napi_ok) {
    raw_snapshot->Dispose();
    return Unavailable(env);
  }
  return result;
}

bool ReadSnapshotCapabilityValue(napi_env env, napi_value capability, SnapshotSession** snapshot) {
  bool tagged = false;
  void* raw_snapshot = nullptr;
  return napi_check_object_type_tag(env, capability, &kSnapshotCapabilityTypeTag, &tagged) == napi_ok && tagged && napi_unwrap(env, capability, &raw_snapshot) == napi_ok && raw_snapshot != nullptr && ((*snapshot = static_cast<SnapshotSession*>(raw_snapshot))->IsValidCapability());
}

bool ReadSnapshotCapability(napi_env env, napi_callback_info info, SnapshotSession** snapshot) {
  size_t count = 1;
  napi_value capability{};
  return napi_get_cb_info(env, info, &count, &capability, nullptr, nullptr) == napi_ok && count == 1 && ReadSnapshotCapabilityValue(env, capability, snapshot);
}

napi_value DisposeKnownHostsSnapshot(napi_env env, napi_callback_info info) {
  SnapshotSession* snapshot = nullptr;
  if (!ReadSnapshotCapability(env, info, &snapshot) || !snapshot->Dispose()) return Unavailable(env);
  napi_value result{};
  return napi_get_undefined(env, &result) == napi_ok ? result : Unavailable(env);
}

napi_value ValidateNativeAgentKeyReadiness(napi_env env, napi_callback_info info) {
  size_t count = 3;
  napi_value arguments[3]{};
  SnapshotSession* snapshot = nullptr;
  int32_t timeout = 0;
  std::wstring host;
  std::wstring user;
  DWORD port = 0;
  if (napi_get_cb_info(env, info, &count, arguments, nullptr, nullptr) != napi_ok || count != 3 ||
      !ReadSnapshotCapabilityValue(env, arguments[0], &snapshot) || !ReadReadinessDescriptor(env, arguments[1], &host, &port, &user) ||
      napi_get_value_int32(env, arguments[2], &timeout) != napi_ok || timeout <= 0 || timeout > 60000 ||
      !ValidateAgentKeyReadiness(snapshot, host, port, user, static_cast<DWORD>(timeout)))
    return Unavailable(env);
  napi_value result{};
  return napi_get_undefined(env, &result) == napi_ok ? result : Unavailable(env);
}

napi_value ResolveOpenSsh(napi_env env, napi_callback_info info) {
  size_t count = 0;
  if (napi_get_cb_info(env, info, &count, nullptr, nullptr, nullptr) != napi_ok || count != 0) return Unavailable(env);
  std::wstring ssh;
  std::wstring ssh_add;
  std::array<DWORD, 4> version{};
  if (!TrustedOpenSsh(&ssh, &ssh_add, &version)) return Unavailable(env);
  napi_value result{};
  napi_value ssh_value{};
  napi_value ssh_add_value{};
  napi_value version_value{};
  const std::wstring version_text = std::to_wstring(version[0]) + L"." + std::to_wstring(version[1]) + L"." + std::to_wstring(version[2]) + L"." + std::to_wstring(version[3]);
  if (napi_create_object(env, &result) != napi_ok || napi_create_string_utf16(env, reinterpret_cast<const char16_t*>(ssh.c_str()), ssh.size(), &ssh_value) != napi_ok || napi_create_string_utf16(env, reinterpret_cast<const char16_t*>(ssh_add.c_str()), ssh_add.size(), &ssh_add_value) != napi_ok || napi_create_string_utf16(env, reinterpret_cast<const char16_t*>(version_text.c_str()), version_text.size(), &version_value) != napi_ok || napi_set_named_property(env, result, "ssh", ssh_value) != napi_ok || napi_set_named_property(env, result, "sshAdd", ssh_add_value) != napi_ok || napi_set_named_property(env, result, "version", version_value) != napi_ok) return Unavailable(env);
  return result;
}

napi_value ProbeSshAdd(napi_env env, napi_callback_info info) {
  size_t count = 1; napi_value argument{}; int32_t timeout = 0;
  if (napi_get_cb_info(env, info, &count, &argument, nullptr, nullptr) != napi_ok || count != 1 || napi_get_value_int32(env, argument, &timeout) != napi_ok || timeout <= 0 || timeout > 60000) return Unavailable(env);
  DWORD exit_code = 1;
  if (ProbeTrustedOpenSsh(static_cast<DWORD>(timeout), &exit_code) != LaunchResult::kCompleted) return Unavailable(env);
  napi_value result{};
  return napi_create_int32(env, static_cast<int32_t>(exit_code), &result) == napi_ok ? result : Unavailable(env);
}

napi_value ReadCredential(napi_env env, napi_callback_info info) {
  std::string locator;
  if (!ReadCredentialLocator(env, info, &locator)) return Unavailable(env);
  std::wstring target = kCredentialTargetPrefix + std::wstring(locator.begin(), locator.end());
  PCREDENTIALW credential = nullptr;
  if (!CredReadW(target.c_str(), CRED_TYPE_GENERIC, 0, &credential) || credential == nullptr || credential->CredentialBlobSize == 0 || credential->CredentialBlobSize > 4096 || (credential->CredentialBlobSize % sizeof(wchar_t)) != 0) {
    if (credential != nullptr) CredFree(credential);
    return Unavailable(env);
  }
  std::wstring password(reinterpret_cast<wchar_t*>(credential->CredentialBlob), credential->CredentialBlobSize / sizeof(wchar_t));
  CredFree(credential);
  if (password.empty() || password.find(L'\0') != std::wstring::npos) return Unavailable(env);
  napi_value result{};
  const napi_status status = napi_create_string_utf16(env, reinterpret_cast<const char16_t*>(password.data()), password.size(), &result);
  std::fill(password.begin(), password.end(), L'\0');
  return status == napi_ok ? result : Unavailable(env);
}

#ifdef SSH_MCP_NATIVE_TEST
bool ReadWideArgument(napi_env env, napi_callback_info info, std::wstring* value) {
  size_t count = 1;
  napi_value argument{};
  if (napi_get_cb_info(env, info, &count, &argument, nullptr, nullptr) != napi_ok || count != 1) return false;
  size_t length = 0;
  if (napi_get_value_string_utf16(env, argument, nullptr, 0, &length) != napi_ok || length == 0 || length >= 32768) return false;
  std::vector<char16_t> buffer(length + 1);
  if (napi_get_value_string_utf16(env, argument, buffer.data(), buffer.size(), &length) != napi_ok) return false;
  value->assign(reinterpret_cast<const wchar_t*>(buffer.data()), length);
  return value->find(L'\0') == std::wstring::npos;
}

napi_value TestSetSnapshotFailure(napi_env env, napi_callback_info info) {
  std::string failure;
  if (!ReadArgumentString(env, info, &failure)) return Unavailable(env);
  g_test_snapshot_fresh_identity_rechecks = 0;
  if (failure == "directory-create") g_test_snapshot_failure = SnapshotFailure::kDirectoryCreate;
  else if (failure == "directory-verify") g_test_snapshot_failure = SnapshotFailure::kDirectoryVerify;
  else if (failure == "directory-identity") g_test_snapshot_failure = SnapshotFailure::kDirectoryIdentity;
  else if (failure == "file-verify") g_test_snapshot_failure = SnapshotFailure::kFileVerify;
  else if (failure == "file-identity") g_test_snapshot_failure = SnapshotFailure::kFileIdentity;
  else if (failure == "write") g_test_snapshot_failure = SnapshotFailure::kWrite;
  else if (failure == "flush") g_test_snapshot_failure = SnapshotFailure::kFlush;
  else if (failure == "file-disposition") g_test_snapshot_failure = SnapshotFailure::kFileDisposition;
  else if (failure == "directory-disposition") g_test_snapshot_failure = SnapshotFailure::kDirectoryDisposition;
  else return Unavailable(env);
  napi_value result{};
  return napi_get_undefined(env, &result) == napi_ok ? result : Unavailable(env);
}

napi_value TestSnapshotFreshIdentityRechecks(napi_env env, napi_callback_info info) {
  size_t count = 0;
  if (napi_get_cb_info(env, info, &count, nullptr, nullptr, nullptr) != napi_ok || count != 0) return Unavailable(env);
  napi_value result{};
  return napi_create_uint32(env, g_test_snapshot_fresh_identity_rechecks, &result) == napi_ok ? result : Unavailable(env);
}

napi_value TestSnapshotArtifactCount(napi_env env, napi_callback_info info) {
  size_t count = 0;
  std::wstring state_root;
  std::wstring known_hosts_root;
  std::vector<BYTE> operator_sid;
  if (napi_get_cb_info(env, info, &count, nullptr, nullptr, nullptr) != napi_ok || count != 0 || !LoadConfiguration(&state_root, &known_hosts_root, &operator_sid)) return Unavailable(env);
  WIN32_FIND_DATAW entry{};
  const std::wstring pattern = state_root + L"\\.ssh-mcp-snapshot-*";
  HANDLE find = FindFirstFileW(pattern.c_str(), &entry);
  DWORD artifacts = 0;
  if (find != INVALID_HANDLE_VALUE) {
    do {
      if ((entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 && (entry.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0) ++artifacts;
    } while (FindNextFileW(find, &entry) != 0);
    const DWORD find_error = GetLastError();
    FindClose(find);
    if (find_error != ERROR_NO_MORE_FILES) return Unavailable(env);
  } else if (GetLastError() != ERROR_FILE_NOT_FOUND) return Unavailable(env);
  napi_value result{};
  return napi_create_uint32(env, artifacts, &result) == napi_ok ? result : Unavailable(env);
}

napi_value TestFinalizeSnapshotCapability(napi_env env, napi_callback_info info) {
  SnapshotSession* snapshot = nullptr;
  if (!ReadSnapshotCapability(env, info, &snapshot)) return Unavailable(env);
  size_t count = 1;
  napi_value capability{};
  void* unwrapped = nullptr;
  if (napi_get_cb_info(env, info, &count, &capability, nullptr, nullptr) != napi_ok || count != 1 || napi_remove_wrap(env, capability, &unwrapped) != napi_ok || unwrapped != snapshot) return Unavailable(env);
  FinalizeSnapshotCapability(env, snapshot, nullptr);
  napi_value result{};
  return napi_get_undefined(env, &result) == napi_ok ? result : Unavailable(env);
}

napi_value TestReadinessDescriptor(napi_env env, napi_callback_info info) {
  size_t count = 1;
  napi_value descriptor{};
  std::wstring host;
  std::wstring user;
  DWORD port = 0;
  if (napi_get_cb_info(env, info, &count, &descriptor, nullptr, nullptr) != napi_ok || count != 1) return Unavailable(env);
  napi_value result{};
  return napi_get_boolean(env, ReadReadinessDescriptor(env, descriptor, &host, &port, &user), &result) == napi_ok ? result : Unavailable(env);
}

napi_value ReplacementRaceResult(napi_env env, bool hook_executed, DWORD replacement_error, bool read_succeeded, const char* stage) {
  napi_value result{};
  napi_value hook_value{};
  napi_value replacement_error_value{};
  napi_value read_value{};
  napi_value stage_value{};
  if (napi_create_object(env, &result) != napi_ok || napi_get_boolean(env, hook_executed, &hook_value) != napi_ok || napi_create_uint32(env, replacement_error, &replacement_error_value) != napi_ok || napi_get_boolean(env, read_succeeded, &read_value) != napi_ok || napi_create_string_utf8(env, stage, NAPI_AUTO_LENGTH, &stage_value) != napi_ok || napi_set_named_property(env, result, "hookExecuted", hook_value) != napi_ok || napi_set_named_property(env, result, "replacementError", replacement_error_value) != napi_ok || napi_set_named_property(env, result, "readSucceeded", read_value) != napi_ok || napi_set_named_property(env, result, "stage", stage_value) != napi_ok) return Unavailable(env);
  return result;
}

bool ReplaceProtectedFileForTest() {
  if (g_test_replacement_is_root) {
    const std::wstring path = g_test_replacement_root + L"\\" + g_test_replacement_leaf;
    const std::wstring original_replacement_file = path + L".replacement";
    const std::wstring replacement_root = g_test_replacement_root + L".replacement";
    const std::wstring replacement_file = replacement_root + L"\\" + g_test_replacement_leaf;
    if (DeleteFileW(path.c_str()) == 0) { g_test_protected_file_replacement_error = GetLastError(); return false; }
    if (DeleteFileW(original_replacement_file.c_str()) == 0) { g_test_protected_file_replacement_error = GetLastError(); return false; }
    if (RemoveDirectoryW(g_test_replacement_root.c_str()) == 0) { g_test_protected_file_replacement_error = GetLastError(); return false; }
    if (CreateDirectoryW(g_test_replacement_root.c_str(), nullptr) == 0) { g_test_protected_file_replacement_error = GetLastError(); return false; }
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    PSID owner = nullptr;
    PACL dacl = nullptr;
    const DWORD get_security = GetNamedSecurityInfoW(const_cast<wchar_t*>(replacement_root.c_str()), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, nullptr, &dacl, nullptr, &descriptor);
    const DWORD set_security = get_security == ERROR_SUCCESS ? SetNamedSecurityInfoW(const_cast<wchar_t*>(g_test_replacement_root.c_str()), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, owner, nullptr, dacl, nullptr) : get_security;
    if (descriptor != nullptr) LocalFree(descriptor);
    if (set_security != ERROR_SUCCESS) { g_test_protected_file_replacement_error = set_security; return false; }
    g_test_protected_file_replacement_succeeded = MoveFileExW(replacement_file.c_str(), path.c_str(), MOVEFILE_WRITE_THROUGH) != 0;
    if (!g_test_protected_file_replacement_succeeded) g_test_protected_file_replacement_error = GetLastError();
    return g_test_protected_file_replacement_succeeded;
  }
  const std::wstring path = g_test_replacement_root + L"\\" + g_test_replacement_leaf;
  g_test_protected_file_replacement_succeeded = DeleteFileW(path.c_str()) != 0 && MoveFileExW((path + L".replacement").c_str(), path.c_str(), MOVEFILE_WRITE_THROUGH) != 0;
  if (!g_test_protected_file_replacement_succeeded) g_test_protected_file_replacement_error = GetLastError();
  return g_test_protected_file_replacement_succeeded;
}

napi_value TestReadReplacementRace(napi_env env, napi_callback_info info) {
  std::wstring target;
  std::wstring state_root;
  std::wstring known_hosts_root;
  std::vector<BYTE> operator_sid;
  if (!ReadWideArgument(env, info, &target)) return Unavailable(env);
  if (!LoadConfiguration(&state_root, &known_hosts_root, &operator_sid)) return ReplacementRaceResult(env, false, ERROR_SUCCESS, false, "configuration");
  if (target == L"state-root") { g_test_replacement_root = state_root; g_test_replacement_leaf = kStateFile; g_test_replacement_is_root = true; }
  else if (target == L"state-leaf") { g_test_replacement_root = state_root; g_test_replacement_leaf = kStateFile; g_test_replacement_is_root = false; }
  else if (target == L"known-hosts-root") { g_test_replacement_root = known_hosts_root; g_test_replacement_leaf = L"production-api.known_hosts"; g_test_replacement_is_root = true; }
  else if (target == L"known-hosts-leaf") { g_test_replacement_root = known_hosts_root; g_test_replacement_leaf = L"production-api.known_hosts"; g_test_replacement_is_root = false; }
  else return Unavailable(env);
  g_test_protected_file_replacement_succeeded = false;
  g_test_protected_file_replacement_error = ERROR_SUCCESS;
  g_test_protected_file_pre_recheck = ReplaceProtectedFileForTest;
  std::vector<BYTE> data;
  const bool read = ReadProtectedFile(g_test_replacement_root, g_test_replacement_leaf, operator_sid.data(), &data);
  g_test_protected_file_pre_recheck = nullptr;
  return ReplacementRaceResult(env, g_test_protected_file_replacement_succeeded, g_test_protected_file_replacement_error, read, "production-read");
}

napi_value TestReadStateFile(napi_env env, napi_callback_info info) {
  std::wstring root;
  std::vector<BYTE> operator_sid;
  std::vector<BYTE> data;
  if (!ReadWideArgument(env, info, &root) || !CurrentUserSid(&operator_sid)) return Unavailable(env);
  napi_value result{};
  return napi_get_boolean(env, ReadProtectedFile(root, kStateFile, operator_sid.data(), &data), &result) == napi_ok ? result : Unavailable(env);
}

class TestOpenSshContext final {
 public:
  TestOpenSshContext(const std::wstring& system, PSID operator_sid)
      : previous_directory_(g_test_system_directory), previous_owner_(g_test_system_owner), system_(system) {
    g_test_system_directory = &system_;
    g_test_system_owner = operator_sid;
  }
  ~TestOpenSshContext() {
    g_test_system_directory = previous_directory_;
    g_test_system_owner = previous_owner_;
  }
  TestOpenSshContext(const TestOpenSshContext&) = delete;
  TestOpenSshContext& operator=(const TestOpenSshContext&) = delete;
 private:
  const std::wstring* previous_directory_;
  PSID previous_owner_;
  std::wstring system_;
};

napi_value TestTrustedOpenSsh(napi_env env, napi_callback_info info) {
  std::wstring system;
  std::vector<BYTE> operator_sid;
  if (!ReadWideArgument(env, info, &system) || !CurrentUserSid(&operator_sid)) return Unavailable(env);
  TestOpenSshContext context(system, operator_sid.data());
  std::wstring ssh;
  std::wstring ssh_add;
  std::array<DWORD, 4> version{};
  napi_value result{};
  return napi_get_boolean(env, TrustedOpenSsh(&ssh, &ssh_add, &version), &result) == napi_ok ? result : Unavailable(env);
}

bool ReplaceOpenSshBeforeLaunch(const std::wstring& ssh_add) {
  g_test_openssh_replacement_attempted = true;
  g_test_openssh_replacement_move_attempted = false;
  g_test_openssh_replacement_succeeded = false;
  g_test_openssh_replacement_error = ERROR_SUCCESS;
  if (g_test_openssh_force_unexpected_replacement_error) {
    g_test_openssh_replacement_error = ERROR_ACCESS_DENIED;
    SetLastError(g_test_openssh_replacement_error);
    return false;
  }
  g_test_openssh_replacement_move_attempted = true;
  g_test_openssh_replacement_succeeded = MoveFileExW(ssh_add.c_str(), (ssh_add + L".fixture-replacement").c_str(), MOVEFILE_WRITE_THROUGH) != 0;
  if (g_test_openssh_replacement_succeeded) return false;
  g_test_openssh_replacement_error = GetLastError();
  // A trusted system object's DACL may reject mutation before its retained
  // handle reports a sharing violation; both are fail-closed protections.
  return g_test_openssh_replacement_error == ERROR_ACCESS_DENIED || g_test_openssh_replacement_error == ERROR_SHARING_VIOLATION;
}

template <bool ForceUnexpectedReplacementError>
napi_value TestOpenSshIdentityBeforeLaunch(napi_env env, napi_callback_info info) {
  size_t count = 0;
  if (napi_get_cb_info(env, info, &count, nullptr, nullptr, nullptr) != napi_ok || count != 0) return Unavailable(env);
  g_test_openssh_replacement_attempted = false;
  g_test_openssh_replacement_move_attempted = false;
  g_test_openssh_replacement_succeeded = false;
  g_test_openssh_force_unexpected_replacement_error = ForceUnexpectedReplacementError;
  g_test_openssh_replacement_error = ERROR_SUCCESS;
  g_test_openssh_pre_launch = ReplaceOpenSshBeforeLaunch;
  DWORD exit_code = 1;
  const LaunchResult launch = ProbeTrustedOpenSsh(5'000, &exit_code);
  g_test_openssh_pre_launch = nullptr;
  g_test_openssh_force_unexpected_replacement_error = false;
  napi_value result{};
  napi_value replacement_blocked{};
  napi_value move_attempted{};
  napi_value replacement_error{};
  napi_value launch_completed{};
  const bool protected_replacement = g_test_openssh_replacement_attempted && g_test_openssh_replacement_move_attempted && !g_test_openssh_replacement_succeeded && (g_test_openssh_replacement_error == ERROR_ACCESS_DENIED || g_test_openssh_replacement_error == ERROR_SHARING_VIOLATION);
  if (napi_create_object(env, &result) != napi_ok || napi_get_boolean(env, protected_replacement, &replacement_blocked) != napi_ok || napi_get_boolean(env, g_test_openssh_replacement_move_attempted, &move_attempted) != napi_ok || napi_create_uint32(env, g_test_openssh_replacement_error, &replacement_error) != napi_ok || napi_get_boolean(env, launch == LaunchResult::kCompleted, &launch_completed) != napi_ok || napi_set_named_property(env, result, "replacementBlocked", replacement_blocked) != napi_ok || napi_set_named_property(env, result, "moveAttempted", move_attempted) != napi_ok || napi_set_named_property(env, result, "replacementError", replacement_error) != napi_ok || napi_set_named_property(env, result, "launchCompleted", launch_completed) != napi_ok) return Unavailable(env);
  return result;
}

napi_value TestSystemOwnerMismatch(napi_env env, napi_callback_info info) {
  size_t count = 0;
  std::wstring system;
  std::vector<BYTE> operator_sid;
  std::vector<BYTE> data;
  if (napi_get_cb_info(env, info, &count, nullptr, nullptr, nullptr) != napi_ok || count != 0 || !SystemDirectory(&system) || !CurrentUserSid(&operator_sid)) return Unavailable(env);
  const bool read = ReadProtectedFile(system, L"cmd.exe", operator_sid.data(), &data);
  napi_value result{};
  return napi_get_boolean(env, read, &result) == napi_ok ? result : Unavailable(env);
}

napi_value TestLaunch(napi_env env, napi_callback_info info) {
  size_t count = 2;
  napi_value arguments[2]{};
  int32_t timeout = 0;
  if (napi_get_cb_info(env, info, &count, arguments, nullptr, nullptr) != napi_ok || count != 2 || napi_get_value_int32(env, arguments[1], &timeout) != napi_ok || timeout <= 0 || timeout > 60000) return Unavailable(env);
  size_t mode_length = 0;
  if (napi_get_value_string_utf8(env, arguments[0], nullptr, 0, &mode_length) != napi_ok || mode_length > 16) return Unavailable(env);
  std::vector<char> mode(mode_length + 1);
  if (napi_get_value_string_utf8(env, arguments[0], mode.data(), mode.size(), &mode_length) != napi_ok) return Unavailable(env);
  std::wstring system;
  if (!SystemDirectory(&system)) return Unavailable(env);
  const std::wstring command_interpreter = system + L"\\cmd.exe";
  const std::wstring powershell = system + L"\\WindowsPowerShell\\v1.0\\powershell.exe";
  std::wstring application = command_interpreter;
  std::wstring command;
  if (strcmp(mode.data(), "exit") == 0) command = L"\"" + command_interpreter + L"\" /d /c exit 23";
  else if (strcmp(mode.data(), "hang") == 0) {
    application = powershell;
    command = L"\"" + powershell + L"\" -NoProfile -NonInteractive -Command \"Start-Sleep -Seconds 30\"";
  }
  else return Unavailable(env);
  DWORD exit_code = 0;
  const LaunchResult launch = LaunchHiddenProcess(application, std::move(command), static_cast<DWORD>(timeout), &exit_code);
  napi_value result{};
  napi_value completed{};
  napi_value timed_out{};
  napi_value exit_code_value{};
  if (launch == LaunchResult::kFailed || napi_create_object(env, &result) != napi_ok || napi_get_boolean(env, launch == LaunchResult::kCompleted, &completed) != napi_ok || napi_get_boolean(env, launch == LaunchResult::kTimedOut, &timed_out) != napi_ok || napi_create_int32(env, static_cast<int32_t>(exit_code), &exit_code_value) != napi_ok || napi_set_named_property(env, result, "completed", completed) != napi_ok || napi_set_named_property(env, result, "timedOut", timed_out) != napi_ok || napi_set_named_property(env, result, "exitCode", exit_code_value) != napi_ok) return Unavailable(env);
  return result;
}
#endif

}  // namespace

NAPI_MODULE_INIT() {
  napi_property_descriptor properties[] = {
    {"readProfileState", nullptr, ReadProfileState, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"readKnownHosts", nullptr, ReadKnownHosts, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"captureKnownHostsSnapshot", nullptr, CaptureKnownHostsSnapshot, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"disposeKnownHostsSnapshot", nullptr, DisposeKnownHostsSnapshot, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"validateAgentKeyReadiness", nullptr, ValidateNativeAgentKeyReadiness, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"resolveOpenSsh", nullptr, ResolveOpenSsh, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"probeSshAdd", nullptr, ProbeSshAdd, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"readCredential", nullptr, ReadCredential, nullptr, nullptr, nullptr, napi_default, nullptr},
#ifdef SSH_MCP_NATIVE_TEST
    {"testReadReplacementRace", nullptr, TestReadReplacementRace, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"testReadStateFile", nullptr, TestReadStateFile, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"testSystemOwnerMismatch", nullptr, TestSystemOwnerMismatch, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"testTrustedOpenSsh", nullptr, TestTrustedOpenSsh, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"testOpenSshIdentityBeforeLaunch", nullptr, TestOpenSshIdentityBeforeLaunch<false>, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"testOpenSshUnexpectedPreLaunchError", nullptr, TestOpenSshIdentityBeforeLaunch<true>, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"testLaunch", nullptr, TestLaunch, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"testSetSnapshotFailure", nullptr, TestSetSnapshotFailure, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"testSnapshotFreshIdentityRechecks", nullptr, TestSnapshotFreshIdentityRechecks, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"testSnapshotArtifactCount", nullptr, TestSnapshotArtifactCount, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"testFinalizeSnapshotCapability", nullptr, TestFinalizeSnapshotCapability, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"testReadinessDescriptor", nullptr, TestReadinessDescriptor, nullptr, nullptr, nullptr, napi_default, nullptr},
#endif
  };
  if (napi_define_properties(env, exports, sizeof(properties) / sizeof(properties[0]), properties) != napi_ok) return nullptr;
  return exports;
}
