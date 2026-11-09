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
#include <shlobj.h>

#include <string>
#include <array>
#include <algorithm>
#include <atomic>
#include <climits>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <sstream>
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
std::atomic<bool> g_test_force_master_reap_timeout{false};
HANDLE g_test_deferred_reaper_gate = nullptr;
HANDLE g_test_master_started_gate = nullptr;
bool g_test_deferred_reaper_completed = false;
napi_deferred g_test_deferred_reaper_completion = nullptr;
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

bool IsDedicatedAgentPublicKey(const std::vector<BYTE>& value) {
  static constexpr char kPrefix[] = "ssh-ed25519 ";
  static constexpr char kSuffix[] = " ssh-mcp-agent";
  size_t size = value.size();
  if (size > 0 && value[size - 1] == '\n') --size;
  if (size > 0 && value[size - 1] == '\r') --size;
  if (size <= sizeof(kPrefix) + sizeof(kSuffix) || std::memcmp(value.data(), kPrefix, sizeof(kPrefix) - 1) != 0 || std::memcmp(value.data() + size - (sizeof(kSuffix) - 1), kSuffix, sizeof(kSuffix) - 1) != 0) return false;
  const size_t encoded_start = sizeof(kPrefix) - 1;
  const size_t encoded_end = size - (sizeof(kSuffix) - 1);
  if (encoded_end <= encoded_start) return false;
  for (size_t index = encoded_start; index < encoded_end; ++index) {
    const unsigned char character = value[index];
    if (!((character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '+' || character == '/' || character == '=')) return false;
  }
  return true;
}

bool ShortNtfsPath(const std::wstring& value, std::wstring* short_path) {
  const DWORD required = GetShortPathNameW(value.c_str(), nullptr, 0);
  if (required == 0 || required >= 32768) return false;
  std::vector<wchar_t> buffer(required + 1);
  const DWORD written = GetShortPathNameW(value.c_str(), buffer.data(), static_cast<DWORD>(buffer.size()));
  if (written == 0 || written >= buffer.size()) return false;
  short_path->assign(buffer.data(), written);
  return IsAbsoluteLocalPath(*short_path) && IsLocalNtfsPath(*short_path) && short_path->find_first_of(L" \t\r\n") == std::wstring::npos;
}

bool DedicatedAgentPublicKeyPath(std::wstring* path) {
  std::wstring state_root;
  std::wstring known_hosts_root;
  std::vector<BYTE> operator_sid;
  std::vector<BYTE> public_key;
  if (!LoadConfiguration(&state_root, &known_hosts_root, &operator_sid)) return false;
  const size_t separator = state_root.find_last_of(L"\\/");
  if (separator == std::wstring::npos || separator <= 2) return false;
  const std::wstring key_root = state_root.substr(0, separator) + L"\\keys";
  static constexpr wchar_t kPublicKeyLeaf[] = L"ssh-mcp-agent-ed25519.pub";
  if (!ReadProtectedFile(key_root, kPublicKeyLeaf, operator_sid.data(), &public_key) || !IsDedicatedAgentPublicKey(public_key)) return false;
  return ShortNtfsPath(key_root + L"\\" + kPublicKeyLeaf, path);
}

class PrivateSecurityAttributes final {
 public:
  explicit PrivateSecurityAttributes(PSID operator_sid, ACCESS_MASK rights = FILE_ALL_ACCESS, bool directory = true) {
    if (operator_sid != nullptr) acl_.resize(sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD) + GetLengthSid(operator_sid));
    const BYTE inheritance = directory ? OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE : NO_INHERITANCE;
    valid_ = operator_sid != nullptr && InitializeAcl(reinterpret_cast<PACL>(acl_.data()), static_cast<DWORD>(acl_.size()), ACL_REVISION) && AddAccessAllowedAceEx(reinterpret_cast<PACL>(acl_.data()), ACL_REVISION, inheritance, rights, operator_sid) && InitializeSecurityDescriptor(&descriptor_, SECURITY_DESCRIPTOR_REVISION) && SetSecurityDescriptorOwner(&descriptor_, operator_sid, FALSE) && SetSecurityDescriptorDacl(&descriptor_, TRUE, reinterpret_cast<PACL>(acl_.data()), FALSE) && SetSecurityDescriptorControl(&descriptor_, SE_DACL_PROTECTED, SE_DACL_PROTECTED);
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
  if (failure == SnapshotFailure::kNone) return false;
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
  // FILE_OPEN_REPARSE_POINT is not documented as compatible with
  // FILE_DIRECTORY_FILE. Refuse any reparse point while resolving the single
  // child name instead; RootDirectory remains the already-verified parent.
  InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE, root, security.descriptor());
  IO_STATUS_BLOCK status{};
  HANDLE raw = INVALID_HANDLE_VALUE;
  const ACCESS_MASK access = directory ? FILE_READ_ATTRIBUTES | READ_CONTROL | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_TRAVERSE | DELETE | SYNCHRONIZE : GENERIC_READ | GENERIC_WRITE | FILE_READ_ATTRIBUTES | READ_CONTROL | DELETE | SYNCHRONIZE;
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

  bool Acquire() {
    bool expected = false;
    return !disposed_ && busy_.compare_exchange_strong(expected, true);
  }

  void Release() { busy_.store(false); }
  bool busy() const { return busy_.load(); }

  bool ReadyKnownHostsPath(std::wstring* path, std::wstring* directory) {
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
    snapshot_file_path_ = final_file;
    *directory = std::move(final_directory);
    *path = std::move(final_file);
    return true;
  }

  bool ReleaseFileForReadiness() {
    if (file_.get() == INVALID_HANDLE_VALUE || snapshot_file_path_.empty() || !file_identity_known_ ||
        !HasIdentity(file_.get(), file_identity_) || !VerifyFile(file_.get(), operator_sid(), false)) return false;
    file_.reset();
    return true;
  }

  bool Dispose() {
    if (disposed_ || busy_.load()) return false;
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
      snapshot_file_path_.clear();
    } else if (!snapshot_file_path_.empty()) {
      Handle reopened(CreateFileW(snapshot_file_path_.c_str(), DELETE | FILE_READ_ATTRIBUTES | READ_CONTROL,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                                  FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
      if (reopened.get() == INVALID_HANDLE_VALUE || !file_identity_known_ || !HasIdentity(reopened.get(), file_identity_) ||
          !VerifyFile(reopened.get(), operator_sid(), false)) return false;
      FILE_DISPOSITION_INFO delete_info{};
      delete_info.DeleteFile = TRUE;
      if (!SetFileInformationByHandle(reopened.get(), FileDispositionInfo, &delete_info, sizeof(delete_info))) return false;
      snapshot_file_path_.clear();
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
  std::wstring snapshot_file_path_;
  FILE_ID_INFO parent_identity_{};
  FILE_ID_INFO directory_identity_{};
  FILE_ID_INFO file_identity_{};
  bool parent_identity_known_ = false;
  bool directory_identity_known_ = false;
  bool file_identity_known_ = false;
  bool directory_fresh_ = false;
  bool file_fresh_ = false;
  bool disposed_ = false;
  std::atomic<bool> busy_{false};
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

LaunchResult LaunchHiddenProcess(const std::wstring& application, std::wstring command, DWORD timeout, DWORD* exit_code, const std::atomic<bool>* cancelled = nullptr) {
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
  const ULONGLONG started = GetTickCount64();
  DWORD wait = WAIT_TIMEOUT;
  while ((cancelled == nullptr || !cancelled->load()) && GetTickCount64() - started < timeout) {
    const DWORD remaining = static_cast<DWORD>(timeout - (GetTickCount64() - started));
    wait = WaitForSingleObject(process_handle.get(), std::min<DWORD>(remaining, 25));
    if (wait == WAIT_OBJECT_0 || wait == WAIT_FAILED) break;
  }
  if (wait == WAIT_TIMEOUT || (cancelled != nullptr && cancelled->load())) {
    if (!TerminateProcess(process_handle.get(), 1) || WaitForSingleObject(process_handle.get(), 1'000) != WAIT_OBJECT_0) return LaunchResult::kFailed;
    return LaunchResult::kTimedOut;
  }
  if (wait != WAIT_OBJECT_0 || !GetExitCodeProcess(process_handle.get(), exit_code)) return LaunchResult::kFailed;
  return LaunchResult::kCompleted;
}

LaunchResult ProbeTrustedOpenSsh(DWORD timeout, DWORD* exit_code, const std::atomic<bool>* cancelled = nullptr) {
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
  return LaunchHiddenProcess(ssh_add, std::move(command), timeout, exit_code, cancelled);
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
#ifdef SSH_MCP_NATIVE_TEST
  if (g_test_master_started_gate != nullptr) SetEvent(g_test_master_started_gate);
#endif
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

bool StopMaster(Handle* master, const std::wstring& ssh, const std::wstring& control_path, const std::wstring& destination, DWORD timeout, const std::atomic<bool>* cancelled = nullptr, Handle* unreaped = nullptr) {
  const ULONGLONG deadline = GetTickCount64() + timeout;
  DWORD ignored = 1;
  const std::vector<std::wstring> exit_arguments = {L"-F", L"none", L"-S", control_path, L"-O", L"exit", L"--", destination};
  if (timeout > 0) LaunchHiddenProcess(ssh, FixedCommandLine(ssh, exit_arguments), timeout, &ignored, cancelled);
  DWORD wait = WAIT_TIMEOUT;
  while (GetTickCount64() < deadline && (cancelled == nullptr || !cancelled->load())) {
    wait = WaitForSingleObject(master->get(), std::min<DWORD>(static_cast<DWORD>(deadline - GetTickCount64()), 25));
    if (wait == WAIT_OBJECT_0 || wait == WAIT_FAILED) break;
  }
  if (wait == WAIT_OBJECT_0) return true;
  if (master->get() == INVALID_HANDLE_VALUE || !TerminateProcess(master->get(), 1)) return false;
#ifdef SSH_MCP_NATIVE_TEST
  if (g_test_force_master_reap_timeout.load()) {
    if (unreaped != nullptr) *unreaped = std::move(*master);
    return false;
  }
#endif
  if (WaitForSingleObject(master->get(), 1'000) == WAIT_OBJECT_0) return true;
  if (unreaped != nullptr) *unreaped = std::move(*master);
  return false;
}

struct NativeReadinessResult final { bool ready = false; Handle unreaped_master; };

NativeReadinessResult ValidateAgentKeyReadiness(SnapshotSession* snapshot, const std::wstring& host, DWORD port, const std::wstring& user, DWORD timeout, const std::atomic<bool>* cancelled = nullptr) {
  NativeReadinessResult result;
  std::wstring known_hosts;
  std::wstring snapshot_directory;
  std::wstring ssh;
  std::wstring ssh_add;
  std::array<DWORD, 4> version{};
  Handle system_handle;
  Handle openssh_handle;
  Handle ssh_add_handle;
  Handle ssh_handle;
  if ((cancelled != nullptr && cancelled->load()) || !snapshot->ReadyKnownHostsPath(&known_hosts, &snapshot_directory) || !TrustedOpenSsh(&ssh, &ssh_add, &version, &system_handle, &openssh_handle, &ssh_add_handle, &ssh_handle)) return result;
  const std::wstring control_path = snapshot_directory + L"\\control";
  const std::wstring destination = user + L"@" + host;
  const std::vector<std::wstring> master_arguments = {
      L"-F", L"none", L"-N", L"-T", L"-n", L"-M", L"-S", control_path,
      L"-o", L"ControlPersist=no", L"-o", L"CanonicalizeHostname=no", L"-o", L"ProxyCommand=none", L"-o", L"ProxyJump=none",
      L"-o", L"HostName=" + host, L"-o", L"BatchMode=yes", L"-o", L"StrictHostKeyChecking=yes", L"-o", L"UserKnownHostsFile=" + known_hosts,
      L"-o", L"GlobalKnownHostsFile=NUL", L"-o", L"PasswordAuthentication=no", L"-o", L"KbdInteractiveAuthentication=no",
      // The approved key is deliberately held only by the current-user agent;
      // no private-key path is available to this native boundary. Restricting
      // identities here would therefore suppress that agent identity.
      L"-o", L"NumberOfPasswordPrompts=0", L"-o", L"IdentitiesOnly=no", L"-p", std::to_wstring(port), L"--", destination};
  Handle master;
  if (!StartHiddenProcess(ssh, FixedCommandLine(ssh, master_arguments), &master)) return result;
  const ULONGLONG started = GetTickCount64();
  bool ready = false;
  while ((cancelled == nullptr || !cancelled->load()) && GetTickCount64() - started < timeout) {
    DWORD master_exit = STILL_ACTIVE;
    if (!GetExitCodeProcess(master.get(), &master_exit) || master_exit != STILL_ACTIVE) break;
    const DWORD remaining = static_cast<DWORD>(timeout - (GetTickCount64() - started));
    DWORD check_exit = 1;
    const std::vector<std::wstring> check_arguments = {L"-F", L"none", L"-S", control_path, L"-O", L"check", L"--", destination};
    if (LaunchHiddenProcess(ssh, FixedCommandLine(ssh, check_arguments), std::max<DWORD>(1, std::min<DWORD>(remaining, 250)), &check_exit, cancelled) == LaunchResult::kCompleted && check_exit == 0) {
      ready = true;
      break;
    }
  }
  const ULONGLONG elapsed = GetTickCount64() - started;
  const DWORD cleanup = elapsed < timeout ? static_cast<DWORD>(timeout - elapsed) : 0;
  result.ready = StopMaster(&master, ssh, control_path, destination, cleanup, cancelled, &result.unreaped_master) && ready && (cancelled == nullptr || !cancelled->load());
  return result;
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

bool KnownLocalAppData(std::wstring* path) {
  PWSTR raw = nullptr;
  if (SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_DONT_VERIFY, nullptr, &raw) != S_OK || raw == nullptr) return false;
  path->assign(raw);
  CoTaskMemFree(raw);
  return IsLocalNtfsPath(*path);
}

bool IsPlainDirectoryHandle(HANDLE handle) {
  FILE_ATTRIBUTE_TAG_INFO tag{};
  BY_HANDLE_FILE_INFORMATION info{};
  return handle != INVALID_HANDLE_VALUE && GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &tag, sizeof(tag)) && (tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0 && GetFileInformationByHandle(handle, &info) && (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

bool OpenVerifiedDirectoryRelative(HANDLE parent, const std::wstring& leaf, bool require_child_creation, Handle* result) {
  if (parent == INVALID_HANDLE_VALUE || leaf.empty() || leaf.size() > USHRT_MAX / sizeof(wchar_t) || leaf.find_first_of(L"\\/") != std::wstring::npos) return false;
  NativeCreateFile create = GetNativeCreateFile();
  if (create == nullptr) return false;
  UNICODE_STRING name{};
  name.Buffer = const_cast<wchar_t*>(leaf.data());
  name.Length = static_cast<USHORT>(leaf.size() * sizeof(wchar_t));
  name.MaximumLength = name.Length;
  OBJECT_ATTRIBUTES attributes{};
  InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE, parent, nullptr);
  IO_STATUS_BLOCK status{};
  HANDLE raw = INVALID_HANDLE_VALUE;
  const ACCESS_MASK access = FILE_READ_ATTRIBUTES | FILE_TRAVERSE | SYNCHRONIZE | (require_child_creation ? FILE_ADD_SUBDIRECTORY : 0);
  const ULONG options = FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT;
  if (create(&raw, access, &attributes, &status, nullptr, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, options, nullptr, 0) < 0 || raw == INVALID_HANDLE_VALUE) return false;
  Handle child(raw);
  if (!IsPlainDirectoryHandle(child.get())) return false;
  *result = std::move(child);
  return true;
}

bool OpenVerifiedLocalAppData(const std::wstring& path, Handle* result) {
  if (!IsLocalNtfsPath(path) || path.size() < 4 || path[1] != L':' || path[2] != L'\\') return false;
  const std::wstring drive_root = path.substr(0, 3);
  Handle current(CreateFileW(drive_root.c_str(), FILE_READ_ATTRIBUTES | FILE_TRAVERSE, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
  std::array<wchar_t, MAX_PATH> filesystem{};
  if (!IsPlainDirectoryHandle(current.get()) || !GetVolumeInformationByHandleW(current.get(), nullptr, 0, nullptr, nullptr, nullptr, filesystem.data(), static_cast<DWORD>(filesystem.size())) || _wcsicmp(filesystem.data(), L"NTFS") != 0) return false;
  size_t cursor = 3;
  while (cursor < path.size()) {
    const size_t next = path.find_first_of(L"\\/", cursor);
    const size_t length = next == std::wstring::npos ? path.size() : next;
    if (length == cursor) return false;
    Handle child;
    if (!OpenVerifiedDirectoryRelative(current.get(), path.substr(cursor, length - cursor), next == std::wstring::npos, &child)) return false;
    current = std::move(child);
    if (next == std::wstring::npos) break;
    cursor = next + 1;
  }
  *result = std::move(current);
  return true;
}

bool ReadProvisionValue(napi_env env, napi_value input, const char* name, napi_value* value) {
  napi_value key{};
  napi_value descriptor{};
  bool has_value = false;
  if (napi_create_string_utf8(env, name, NAPI_AUTO_LENGTH, &key) != napi_ok || napi_get_own_property_descriptor(env, input, key, &descriptor) != napi_ok || napi_has_named_property(env, descriptor, "value", &has_value) != napi_ok || !has_value) return false;
  return napi_get_named_property(env, descriptor, "value", value) == napi_ok;
}

bool ReadProvisionString(napi_env env, napi_value input, const char* name, std::string* value, size_t maximum) {
  napi_value property{};
  size_t size = 0;
  if (!ReadProvisionValue(env, input, name, &property) || napi_get_value_string_utf8(env, property, nullptr, 0, &size) != napi_ok || size == 0 || size > maximum) return false;
  std::vector<char> buffer(size + 1);
  if (napi_get_value_string_utf8(env, property, buffer.data(), buffer.size(), &size) != napi_ok) return false;
  value->assign(buffer.data(), size);
  return value->find('\0') == std::string::npos;
}

bool IsDnsHost(const std::string& value) {
  if (value.empty() || value.size() > 253 || value.back() == '.' || value.front() == '-' || value.front() == '.') return false;
  for (size_t index = 0; index < value.size(); ++index) {
    const char c = value[index];
    if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-') || (c == '-' && (index == 0 || value[index - 1] == '.')) || (c == '.' && (index == 0 || value[index - 1] == '.'))) return false;
  }
  return true;
}

bool IsCanonicalUser(const std::string& value) {
  if (value.empty() || value.size() > 64 || value.front() == '-') return false;
  for (char c : value) if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-')) return false;
  return true;
}

bool IsFingerprint(const std::string& value) {
  if (value.size() != 50 || value.rfind("SHA256:", 0) != 0) return false;
  for (size_t index = 7; index < value.size(); ++index) if (!((value[index] >= 'A' && value[index] <= 'Z') || (value[index] >= 'a' && value[index] <= 'z') || (value[index] >= '0' && value[index] <= '9') || value[index] == '+' || value[index] == '/')) return false;
  return true;
}

bool IsCredentialLocator(const std::string& value) {
  if (value.empty() || value.size() > 128 || value.front() < 'a' || value.front() > 'z' || value.find("..") != std::string::npos) return false;
  for (char c : value) if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == ':' || c == '-')) return false;
  for (const char* prefix : {"password", "passphrase", "private-key", "private_key", "secret", "token"}) {
    const size_t size = strlen(prefix);
    if (value.rfind(prefix, 0) == 0 && (value.size() == size || value[size] == '.' || value[size] == '_' || value[size] == ':' || value[size] == '-')) return false;
  }
  return true;
}

bool Base64Sha256(const std::string& encoded, std::string* fingerprint) {
  DWORD bytes = 0;
  if (!CryptStringToBinaryA(encoded.c_str(), static_cast<DWORD>(encoded.size()), CRYPT_STRING_BASE64, nullptr, &bytes, nullptr, nullptr) || bytes == 0) return false;
  std::vector<BYTE> key(bytes);
  if (!CryptStringToBinaryA(encoded.c_str(), static_cast<DWORD>(encoded.size()), CRYPT_STRING_BASE64, key.data(), &bytes, nullptr, nullptr)) return false;
  BCRYPT_ALG_HANDLE algorithm = nullptr;
  DWORD object_bytes = 0, hash_bytes = 0, returned = 0;
  if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0 || BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_bytes), sizeof(object_bytes), &returned, 0) != 0 || BCryptGetProperty(algorithm, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hash_bytes), sizeof(hash_bytes), &returned, 0) != 0) { if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0); return false; }
  std::vector<BYTE> object(object_bytes), hash(hash_bytes);
  BCRYPT_HASH_HANDLE handle = nullptr;
  const bool hashed = BCryptCreateHash(algorithm, &handle, object.data(), object_bytes, nullptr, 0, 0) == 0 && BCryptHashData(handle, key.data(), bytes, 0) == 0 && BCryptFinishHash(handle, hash.data(), hash_bytes, 0) == 0;
  if (handle) BCryptDestroyHash(handle);
  BCryptCloseAlgorithmProvider(algorithm, 0);
  DWORD text = 0;
  if (!hashed || !CryptBinaryToStringA(hash.data(), hash_bytes, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &text)) return false;
  std::string output(text, '\0');
  if (!CryptBinaryToStringA(hash.data(), hash_bytes, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, output.data(), &text)) return false;
  output.resize(text);
  if (!output.empty() && output.back() == '\0') output.pop_back();
  while (!output.empty() && output.back() == '=') output.pop_back();
  *fingerprint = "SHA256:" + output;
  return true;
}

bool VerifyKnownHostLine(const std::string& line, const std::string& host, DWORD port, const std::string& expected) {
  if (line.empty() || line.size() > 16384 || line.find_first_of("\r\n\0") != std::string::npos) return false;
  std::istringstream stream(line);
  std::string endpoint, algorithm, key, extra;
  if (!(stream >> endpoint >> algorithm >> key) || (stream >> extra)) return false;
  const std::string expected_endpoint = port == 22 ? host : "[" + host + "]:" + std::to_string(port);
  if (endpoint != expected_endpoint || (algorithm != "ssh-ed25519" && algorithm != "ssh-rsa" && algorithm != "ssh-dss" && algorithm != "ecdsa-sha2-nistp256" && algorithm != "ecdsa-sha2-nistp384" && algorithm != "ecdsa-sha2-nistp521")) return false;
  std::string actual;
  return Base64Sha256(key, &actual) && actual == expected;
}

bool IsExactProvisionObject(napi_env env, napi_value input, bool password) {
  napi_value prototype{}, object{}, expected{}, names{};
  uint32_t length = 0;
  bool same_prototype = false;
  if (napi_get_prototype(env, input, &prototype) != napi_ok || napi_get_global(env, &object) != napi_ok || napi_get_named_property(env, object, "Object", &object) != napi_ok || napi_get_named_property(env, object, "prototype", &expected) != napi_ok || napi_strict_equals(env, prototype, expected, &same_prototype) != napi_ok || !same_prototype || napi_get_all_property_names(env, input, napi_key_own_only, napi_key_include_all, napi_key_numbers_to_strings, &names) != napi_ok || napi_get_array_length(env, names, &length) != napi_ok || length != (password ? 8u : 7u)) return false;
  const char* allowed[] = {"profileId", "host", "port", "user", "authMode", "expectedHostFingerprint", "hostKeyLine", "credentialLocator"};
  for (uint32_t index = 0; index < length; ++index) {
    napi_value name{};
    size_t bytes = 0;
    if (napi_get_element(env, names, index, &name) != napi_ok || napi_get_value_string_utf8(env, name, nullptr, 0, &bytes) != napi_ok || bytes > 32) return false;
    std::vector<char> key(bytes + 1);
    if (napi_get_value_string_utf8(env, name, key.data(), key.size(), &bytes) != napi_ok) return false;
    bool recognized = false;
    for (size_t allowed_index = 0; allowed_index < (password ? 8u : 7u); ++allowed_index) recognized = recognized || strcmp(key.data(), allowed[allowed_index]) == 0;
    if (!recognized) return false;
  }
  return true;
}

std::string JsonString(const std::string& value) {
  std::string result = "\"";
  for (unsigned char c : value) {
    if (c == '\\') result += "\\\\";
    else if (c == '\"') result += "\\\"";
    else if (c < 0x20) result += "\\u00" + std::string(1, "0123456789abcdef"[c >> 4]) + std::string(1, "0123456789abcdef"[c & 15]);
    else result += static_cast<char>(c);
  }
  return result + "\"";
}

bool IsCanonicalProfileId(const std::string& value) {
  if (value.empty() || value.size() > 128) return false;
  for (const char* reserved : {"con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9", "constructor", "prototype", "__proto__"}) if (value == reserved) return false;
  for (size_t index = 0; index < value.size(); ++index) if (!((value[index] >= 'a' && value[index] <= 'z') || (value[index] >= '0' && value[index] <= '9') || (value[index] == '-' && index > 0 && index + 1 < value.size() && value[index - 1] != '-'))) return false;
  return true;
}

napi_value ProvisionApprovedProfile(napi_env env, napi_callback_info info) {
  size_t count = 1;
  napi_value arguments[1]{};
  napi_valuetype type{};
  if (napi_get_cb_info(env, info, &count, arguments, nullptr, nullptr) != napi_ok || count != 1 || napi_typeof(env, arguments[0], &type) != napi_ok || type != napi_object) return Unavailable(env);
  std::string profile_id, host, user, mode, locator, fingerprint, known_host_line;
  napi_value port_value{};
  double port = 0;
  if (!ReadProvisionString(env, arguments[0], "authMode", &mode, 16) || (mode != "agent-key" && mode != "password") || !IsExactProvisionObject(env, arguments[0], mode == "password") || !ReadProvisionString(env, arguments[0], "profileId", &profile_id, 128) || !ReadProvisionString(env, arguments[0], "host", &host, 253) || !ReadProvisionString(env, arguments[0], "user", &user, 64) || !ReadProvisionString(env, arguments[0], "expectedHostFingerprint", &fingerprint, 64) || !ReadProvisionString(env, arguments[0], "hostKeyLine", &known_host_line, 16384) || !IsCanonicalProfileId(profile_id) || !IsDnsHost(host) || !IsCanonicalUser(user) || !IsFingerprint(fingerprint) || !ReadProvisionValue(env, arguments[0], "port", &port_value) || napi_get_value_double(env, port_value, &port) != napi_ok || !std::isfinite(port) || std::floor(port) != port || port < 1 || port > 65535) return Unavailable(env);
  if (mode == "password" && (!ReadProvisionString(env, arguments[0], "credentialLocator", &locator, 128) || !IsCredentialLocator(locator))) return Unavailable(env);
  if (!VerifyKnownHostLine(known_host_line, host, static_cast<DWORD>(port), fingerprint)) return Unavailable(env);
  std::wstring local_app_data;
  std::vector<BYTE> sid;
  if (!KnownLocalAppData(&local_app_data) || !CurrentUserSid(&sid)) return Unavailable(env);
  const std::wstring base = local_app_data + L"\\Vissoto\\ssh-mcp-server";
  const std::wstring state = base + L"\\state";
  const std::wstring known = base + L"\\known-hosts";
  const std::wstring state_file = state + L"\\connection-profiles.json";
  const std::wstring known_file = known + L"\\" + std::wstring(profile_id.begin(), profile_id.end()) + L".known_hosts";
  HKEY existing = nullptr;
  if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Vissoto", 0, KEY_READ, &existing) == ERROR_SUCCESS) { RegCloseKey(existing); return Unavailable(env); }
  Handle local_handle;
  if (!OpenVerifiedLocalAppData(local_app_data, &local_handle)) return Unavailable(env);
  PrivateSecurityAttributes file_security(sid.data());
  if (!file_security.valid()) return Unavailable(env);
  Handle vendor_handle, base_handle, state_handle, known_handle, known_file_handle, state_file_handle;
  if (!CreatePrivateRelative(local_handle.get(), L"Vissoto", file_security, true, SnapshotFailure::kNone, &vendor_handle) || !VerifyFile(vendor_handle.get(), sid.data(), true) || !CreatePrivateRelative(vendor_handle.get(), L"ssh-mcp-server", file_security, true, SnapshotFailure::kNone, &base_handle) || !VerifyFile(base_handle.get(), sid.data(), true) || !CreatePrivateRelative(base_handle.get(), L"state", file_security, true, SnapshotFailure::kNone, &state_handle) || !VerifyFile(state_handle.get(), sid.data(), true) || !CreatePrivateRelative(base_handle.get(), L"known-hosts", file_security, true, SnapshotFailure::kNone, &known_handle) || !VerifyFile(known_handle.get(), sid.data(), true)) return Unavailable(env);
  const std::string credential = mode == "password" ? ",\n      \"credentialReference\": " + JsonString("os://ssh/" + locator) : "";
  const std::string state_json = "{\n  \"profiles\": [\n    {\n      \"profileId\": " + JsonString(profile_id) + ",\n      \"host\": " + JsonString(host) + ",\n      \"port\": " + std::to_string(static_cast<int>(port)) + ",\n      \"user\": " + JsonString(user) + ",\n      \"expectedHostFingerprint\": " + JsonString(fingerprint) + ",\n      \"authMode\": " + JsonString(mode) + ",\n      \"approvedKnownHostsReference\": " + JsonString("known-hosts://" + profile_id) + credential + "\n    }\n  ]\n}\n";
  const auto write_new_file = [&](HANDLE parent, const std::wstring& leaf, const std::string& content, Handle* retained) {
    if (!CreatePrivateRelative(parent, leaf, file_security, false, SnapshotFailure::kNone, retained) || !VerifyFile(retained->get(), sid.data(), false) || content.size() > MAXDWORD) return false;
    DWORD written = 0;
    return WriteFile(retained->get(), content.data(), static_cast<DWORD>(content.size()), &written, nullptr) && written == content.size() && FlushFileBuffers(retained->get()) && VerifyFile(retained->get(), sid.data(), false);
  };
  if (!write_new_file(known_handle.get(), std::wstring(profile_id.begin(), profile_id.end()) + L".known_hosts", known_host_line + "\n", &known_file_handle) || !write_new_file(state_handle.get(), kStateFile, state_json, &state_file_handle)) return Unavailable(env);
  HKEY vendor_key = nullptr;
  DWORD disposition = 0;
  PrivateSecurityAttributes registry_security(sid.data(), KEY_ALL_ACCESS, false);
  if (!registry_security.valid() || RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Vissoto", 0, nullptr, 0, KEY_READ | KEY_WRITE | READ_CONTROL | WRITE_DAC | WRITE_OWNER, registry_security.get(), &vendor_key, &disposition) != ERROR_SUCCESS || disposition != REG_CREATED_NEW_KEY) return Unavailable(env);
  RegistryKey vendor_registry(vendor_key);
  if (!VerifyRegistryConfiguration(vendor_registry.get(), sid.data())) return Unavailable(env);
  HKEY config_key = nullptr;
  if (RegCreateKeyExW(vendor_registry.get(), L"ssh-mcp-server", 0, nullptr, 0, KEY_READ | KEY_WRITE | READ_CONTROL | WRITE_DAC | WRITE_OWNER, registry_security.get(), &config_key, &disposition) != ERROR_SUCCESS || disposition != REG_CREATED_NEW_KEY) return Unavailable(env);
  RegistryKey config(config_key);
  if (!VerifyRegistryConfiguration(config.get(), sid.data()) || RegSetValueExW(config.get(), L"StateRoot", 0, REG_SZ, reinterpret_cast<const BYTE*>(state.c_str()), static_cast<DWORD>((state.size() + 1) * sizeof(wchar_t))) != ERROR_SUCCESS || RegSetValueExW(config.get(), L"KnownHostsRoot", 0, REG_SZ, reinterpret_cast<const BYTE*>(known.c_str()), static_cast<DWORD>((known.size() + 1) * sizeof(wchar_t))) != ERROR_SUCCESS) return Unavailable(env);
  napi_value result{};
  return napi_get_undefined(env, &result) == napi_ok ? result : Unavailable(env);
}

napi_value ReadProfileState(napi_env env, napi_callback_info) {
  std::wstring state_root;
  std::wstring known_hosts_root;
  std::vector<BYTE> operator_sid;
  std::vector<BYTE> data;
  if (!LoadConfiguration(&state_root, &known_hosts_root, &operator_sid) || !ReadProtectedFile(state_root, kStateFile, operator_sid.data(), &data)) return Unavailable(env);
  return ToBuffer(env, data);
}

// Exposes only fixed local-prerequisite categories. In particular, this probe
// never returns configured roots, profile contents, known-hosts data, or any
// Credential Manager value.
napi_value InspectReadiness(napi_env env, napi_callback_info info) {
  size_t count = 0;
  if (napi_get_cb_info(env, info, &count, nullptr, nullptr, nullptr) != napi_ok || count != 0) return Unavailable(env);

  const char* registry = "unavailable";
  const char* filesystem = "not-checked";
  const char* configuration = "not-checked";
  std::vector<BYTE> operator_sid;
  HKEY raw_key = nullptr;
  std::wstring state_root;
  std::wstring known_hosts_root;
  std::vector<BYTE> state;

  if (!CurrentUserSid(&operator_sid) ||
      RegOpenKeyExW(HKEY_CURRENT_USER, kConfigurationKey, 0, KEY_READ | READ_CONTROL, &raw_key) != ERROR_SUCCESS) {
    goto result;
  }
  {
    RegistryKey key(raw_key);
    raw_key = nullptr;
    if (!VerifyRegistryConfiguration(key.get(), operator_sid.data())) goto result;
    registry = "ready";
    if (!ReadStringValue(key.get(), L"StateRoot", &state_root) || !ReadStringValue(key.get(), L"KnownHostsRoot", &known_hosts_root) ||
        !IsLocalNtfsPath(state_root) || !IsLocalNtfsPath(known_hosts_root)) {
      configuration = "unavailable";
      goto result;
    }
  }
  if (!VerifyDirectoryChain(state_root, operator_sid.data()) || !VerifyDirectoryChain(known_hosts_root, operator_sid.data())) {
    filesystem = "unavailable";
    goto result;
  }
  filesystem = "ready";
  // Root identity and nesting are configuration properties. Directory-chain
  // safety is checked first so absent, unsafe, or reparse roots are reported
  // as a filesystem prerequisite rather than an ambiguous configuration error.
  if (!RootsAreDistinct(state_root, known_hosts_root, operator_sid.data())) {
    configuration = "unavailable";
    goto result;
  }
  if (!ReadProtectedFile(state_root, kStateFile, operator_sid.data(), &state)) {
    configuration = "unavailable";
    goto result;
  }
  configuration = "ready";

result:
  if (raw_key != nullptr) RegCloseKey(raw_key);
  napi_value result{};
  napi_value registry_value{};
  napi_value filesystem_value{};
  napi_value configuration_value{};
  if (napi_create_object(env, &result) != napi_ok ||
      napi_create_string_utf8(env, registry, NAPI_AUTO_LENGTH, &registry_value) != napi_ok ||
      napi_create_string_utf8(env, filesystem, NAPI_AUTO_LENGTH, &filesystem_value) != napi_ok ||
      napi_create_string_utf8(env, configuration, NAPI_AUTO_LENGTH, &configuration_value) != napi_ok ||
      napi_set_named_property(env, result, "registry", registry_value) != napi_ok ||
      napi_set_named_property(env, result, "filesystem", filesystem_value) != napi_ok ||
      napi_set_named_property(env, result, "configuration", configuration_value) != napi_ok) {
    return Unavailable(env);
  }
  return result;
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

napi_value IsKnownHostsSnapshotBusy(napi_env env, napi_callback_info info) {
  SnapshotSession* snapshot = nullptr;
  if (!ReadSnapshotCapability(env, info, &snapshot)) return Unavailable(env);
  napi_value result{};
  return napi_get_boolean(env, snapshot->busy(), &result) == napi_ok ? result : Unavailable(env);
}

// This prepares only native-verified, current-user paths for the TypeScript
// process runner. The MCP protocol never accepts or returns either path.
napi_value PrepareAgentKeyReadiness(napi_env env, napi_callback_info info) {
  SnapshotSession* snapshot = nullptr;
  std::wstring known_hosts;
  std::wstring snapshot_directory;
  std::wstring known_hosts_short;
  std::wstring identity_file;
  if (!ReadSnapshotCapability(env, info, &snapshot) || snapshot->busy() ||
      !snapshot->ReadyKnownHostsPath(&known_hosts, &snapshot_directory) ||
      !ShortNtfsPath(known_hosts, &known_hosts_short) || !snapshot->ReleaseFileForReadiness() ||
      !DedicatedAgentPublicKeyPath(&identity_file)) return Unavailable(env);
  napi_value result{};
  napi_value known_hosts_value{};
  napi_value identity_file_value{};
  if (napi_create_object(env, &result) != napi_ok ||
      napi_create_string_utf16(env, reinterpret_cast<const char16_t*>(known_hosts_short.c_str()), known_hosts_short.size(), &known_hosts_value) != napi_ok ||
      napi_create_string_utf16(env, reinterpret_cast<const char16_t*>(identity_file.c_str()), identity_file.size(), &identity_file_value) != napi_ok ||
      napi_set_named_property(env, result, "knownHostsPath", known_hosts_value) != napi_ok ||
      napi_set_named_property(env, result, "identityFile", identity_file_value) != napi_ok) return Unavailable(env);
  return result;
}

struct NativeCancellation final { std::atomic<bool> requested{false}; };
struct AgentReadinessWork final {
  napi_env env;
  napi_async_work work = nullptr;
  napi_deferred deferred = nullptr;
  napi_ref snapshot_reference = nullptr;
  SnapshotSession* snapshot = nullptr;
  std::wstring host;
  std::wstring user;
  DWORD port = 0;
  DWORD timeout = 0;
  std::shared_ptr<NativeCancellation> cancellation;
  bool succeeded = false;
  Handle unreaped_master;
};

void ExecuteAgentReadiness(napi_env, void* data) {
  auto* job = static_cast<AgentReadinessWork*>(data);
  if (job->cancellation->requested.load()) return;
  NativeReadinessResult result = ValidateAgentKeyReadiness(job->snapshot, job->host, job->port, job->user, job->timeout, &job->cancellation->requested);
  job->succeeded = result.ready;
  job->unreaped_master = std::move(result.unreaped_master);
}

struct DeferredReaperWork final {
  napi_threadsafe_function completion = nullptr;
  HANDLE wait_registration = nullptr;
  napi_ref snapshot_reference = nullptr;
  SnapshotSession* snapshot = nullptr;
  Handle child;
};

// This callback runs on the Windows thread-pool, rather than a libuv worker.
// It never touches N-API directly; the threadsafe function below transfers
// final ownership back to the JS thread after the child is confirmed exited.
VOID CALLBACK DeferredReaperWaitCallback(PVOID data, BOOLEAN) {
  auto* reaper = static_cast<DeferredReaperWork*>(data);
#ifdef SSH_MCP_NATIVE_TEST
  if (g_test_deferred_reaper_gate != nullptr) WaitForSingleObject(g_test_deferred_reaper_gate, INFINITE);
#endif
  // A failed queue must retain the busy lease and reference for process
  // lifetime: releasing a snapshot before this child is known dead is unsafe.
  napi_call_threadsafe_function(reaper->completion, nullptr, napi_tsfn_nonblocking);
}

void CompleteDeferredReaper(napi_env env, napi_value, void* data, void*) {
  std::unique_ptr<DeferredReaperWork> reaper(static_cast<DeferredReaperWork*>(data));
  reaper->snapshot->Release();
  // The surrounding TypeScript finally deliberately left this capability busy.
  // Its native owner must now complete its deterministic cleanup itself.
  if (!reaper->snapshot->Dispose()) {
    // Cleanup uncertainty is fail-closed: retain the capability reference and
    // reacquire its lease for process lifetime rather than allow finalization
    // to race an unverified retry.
    reaper->snapshot->Acquire();
    if (reaper->completion != nullptr) napi_release_threadsafe_function(reaper->completion, napi_tsfn_release);
    reaper.release();
    return;
  }
  if (reaper->snapshot_reference != nullptr) napi_delete_reference(env, reaper->snapshot_reference);
#ifdef SSH_MCP_NATIVE_TEST
  g_test_deferred_reaper_completed = true;
  if (g_test_deferred_reaper_completion != nullptr) {
    napi_value result{};
    napi_get_undefined(env, &result);
    napi_resolve_deferred(env, g_test_deferred_reaper_completion, result);
    g_test_deferred_reaper_completion = nullptr;
  }
#endif
  if (reaper->completion != nullptr) napi_release_threadsafe_function(reaper->completion, napi_tsfn_release);
}

napi_value DeferredReaperNoop(napi_env env, napi_callback_info) {
  napi_value value{};
  return napi_get_undefined(env, &value) == napi_ok ? value : nullptr;
}

bool ScheduleDeferredReaper(napi_env env, std::unique_ptr<DeferredReaperWork>& reaper) {
  napi_value name{};
  napi_value callback{};
  if (napi_create_string_utf8(env, "sshMcpDeferredReaper", NAPI_AUTO_LENGTH, &name) != napi_ok ||
      napi_create_function(env, "reap", NAPI_AUTO_LENGTH, DeferredReaperNoop, nullptr, &callback) != napi_ok ||
      napi_create_threadsafe_function(env, callback, nullptr, name, 0, 1, nullptr, nullptr, reaper.get(), CompleteDeferredReaper, &reaper->completion) != napi_ok) {
    return false;
  }
  if (!RegisterWaitForSingleObject(&reaper->wait_registration, reaper->child.get(), DeferredReaperWaitCallback, reaper.get(), INFINITE, WT_EXECUTEONLYONCE)) {
    napi_release_threadsafe_function(reaper->completion, napi_tsfn_abort);
    reaper->completion = nullptr;
    return false;
  }
  reaper.release();
  return true;
}

void CompleteAgentReadiness(napi_env env, napi_status, void* data) {
  std::unique_ptr<AgentReadinessWork> job(static_cast<AgentReadinessWork*>(data));
  bool deferred = false;
  if (job->unreaped_master.get() != INVALID_HANDLE_VALUE) {
    auto reaper = std::make_unique<DeferredReaperWork>();
    reaper->snapshot = job->snapshot;
    reaper->snapshot_reference = job->snapshot_reference;
    reaper->child = std::move(job->unreaped_master);
    if (ScheduleDeferredReaper(env, reaper)) {
      job->snapshot_reference = nullptr;
      deferred = true;
    } else {
      // Preserve the busy lease and reference for process lifetime rather than
      // releasing a snapshot which an unreaped child can still read.
      // ScheduleDeferredReaper leaves its input intact on failure. Retain the
      // child, reference and busy lease for process lifetime rather than
      // risking early snapshot release.
      reaper.release();
      job->snapshot_reference = nullptr;
      deferred = true;
    }
  }
  if (!deferred) {
    job->snapshot->Release();
    if (job->snapshot_reference != nullptr) napi_delete_reference(env, job->snapshot_reference);
  }
  if (job->work != nullptr) napi_delete_async_work(env, job->work);
  if (job->succeeded && !job->cancellation->requested.load()) {
    napi_value result{};
    napi_get_undefined(env, &result);
    napi_resolve_deferred(env, job->deferred, result);
  } else {
    napi_value message{};
    napi_value error{};
    napi_create_string_utf8(env, "Windows connection validation is unavailable", NAPI_AUTO_LENGTH, &message);
    napi_create_error(env, nullptr, message, &error);
    napi_reject_deferred(env, job->deferred, error);
  }
}

void FinalizeAgentReadinessCancellation(napi_env, void* data, void*) { delete static_cast<std::shared_ptr<NativeCancellation>*>(data); }

napi_value CancelAgentReadiness(napi_env env, napi_callback_info info) {
  void* data = nullptr;
  size_t count = 0;
  if (napi_get_cb_info(env, info, &count, nullptr, nullptr, &data) != napi_ok || data == nullptr) return Unavailable(env);
  static_cast<std::shared_ptr<NativeCancellation>*>(data)->get()->requested.store(true);
  napi_value result{};
  return napi_get_undefined(env, &result) == napi_ok ? result : Unavailable(env);
}

napi_value StartNativeAgentKeyReadiness(napi_env env, napi_callback_info info) {
  size_t count = 3;
  napi_value arguments[3]{};
  int32_t timeout = 0;
  auto job = std::make_unique<AgentReadinessWork>();
  job->env = env;
  if (napi_get_cb_info(env, info, &count, arguments, nullptr, nullptr) != napi_ok || count != 3 || !ReadSnapshotCapabilityValue(env, arguments[0], &job->snapshot) || !job->snapshot->Acquire()) return Unavailable(env);
  if (!ReadReadinessDescriptor(env, arguments[1], &job->host, &job->port, &job->user) || napi_get_value_int32(env, arguments[2], &timeout) != napi_ok || timeout <= 0 || timeout > 60000) { job->snapshot->Release(); return Unavailable(env); }
  job->timeout = static_cast<DWORD>(timeout);
  job->cancellation = std::make_shared<NativeCancellation>();
  napi_value promise{};
  napi_value resource_name{};
  napi_value cancel{};
  napi_value result{};
  auto cancellation_handle = std::make_unique<std::shared_ptr<NativeCancellation>>(job->cancellation);
  if (napi_create_promise(env, &job->deferred, &promise) != napi_ok || napi_create_string_utf8(env, "sshMcpAgentReadiness", NAPI_AUTO_LENGTH, &resource_name) != napi_ok || napi_create_function(env, "cancel", NAPI_AUTO_LENGTH, CancelAgentReadiness, cancellation_handle.get(), &cancel) != napi_ok) { job->snapshot->Release(); return Unavailable(env); }
  if (napi_add_finalizer(env, cancel, cancellation_handle.get(), FinalizeAgentReadinessCancellation, nullptr, nullptr) != napi_ok) { job->snapshot->Release(); return Unavailable(env); }
  cancellation_handle.release();
  if (napi_create_object(env, &result) != napi_ok || napi_set_named_property(env, result, "promise", promise) != napi_ok || napi_set_named_property(env, result, "cancel", cancel) != napi_ok) { job->snapshot->Release(); return Unavailable(env); }
  if (napi_create_reference(env, arguments[0], 1, &job->snapshot_reference) != napi_ok) { job->snapshot->Release(); return Unavailable(env); }
  if (napi_create_async_work(env, nullptr, resource_name, ExecuteAgentReadiness, CompleteAgentReadiness, job.get(), &job->work) != napi_ok) {
    napi_delete_reference(env, job->snapshot_reference);
    job->snapshot_reference = nullptr;
    job->snapshot->Release();
    return Unavailable(env);
  }
  if (napi_queue_async_work(env, job->work) != napi_ok) {
    napi_delete_async_work(env, job->work);
    job->work = nullptr;
    napi_delete_reference(env, job->snapshot_reference);
    job->snapshot_reference = nullptr;
    job->snapshot->Release();
    return Unavailable(env);
  }
  job.release();
  return result;
}

// The ssh-add identity gate is deliberately native and asynchronous. It keeps
// the same verified OpenSSH chain through launch, and cancellation reaches the
// actual hidden child instead of merely racing a JS-side synchronous call.
struct SshAddProbeWork final {
  napi_env env;
  napi_async_work work = nullptr;
  napi_deferred deferred = nullptr;
  DWORD timeout = 0;
  std::shared_ptr<NativeCancellation> cancellation;
  bool available = false;
};

void ExecuteSshAddProbe(napi_env, void* data) {
  auto* job = static_cast<SshAddProbeWork*>(data);
  if (job->cancellation->requested.load()) return;
  DWORD exit_code = 1;
  const LaunchResult probe = ProbeTrustedOpenSsh(job->timeout, &exit_code, &job->cancellation->requested);
  job->available = probe == LaunchResult::kCompleted && exit_code == 0 && !job->cancellation->requested.load();
}

void CompleteSshAddProbe(napi_env env, napi_status, void* data) {
  std::unique_ptr<SshAddProbeWork> job(static_cast<SshAddProbeWork*>(data));
  if (job->work != nullptr) napi_delete_async_work(env, job->work);
  if (job->cancellation->requested.load()) {
    napi_value message{};
    napi_value error{};
    napi_create_string_utf8(env, "Windows OpenSSH is unavailable", NAPI_AUTO_LENGTH, &message);
    napi_create_error(env, nullptr, message, &error);
    napi_reject_deferred(env, job->deferred, error);
    return;
  }
  napi_value available{};
  if (napi_get_boolean(env, job->available, &available) != napi_ok) {
    napi_value message{};
    napi_value error{};
    napi_create_string_utf8(env, "Windows OpenSSH is unavailable", NAPI_AUTO_LENGTH, &message);
    napi_create_error(env, nullptr, message, &error);
    napi_reject_deferred(env, job->deferred, error);
    return;
  }
  napi_resolve_deferred(env, job->deferred, available);
}

napi_value StartSshAddProbe(napi_env env, napi_callback_info info) {
  size_t count = 1;
  napi_value argument{};
  int32_t timeout = 0;
  if (napi_get_cb_info(env, info, &count, &argument, nullptr, nullptr) != napi_ok || count != 1 ||
      napi_get_value_int32(env, argument, &timeout) != napi_ok || timeout <= 0 || timeout > 60000) return Unavailable(env);
  auto job = std::make_unique<SshAddProbeWork>();
  job->env = env;
  job->timeout = static_cast<DWORD>(timeout);
  job->cancellation = std::make_shared<NativeCancellation>();
  napi_value promise{};
  napi_value resource_name{};
  napi_value cancel{};
  napi_value result{};
  auto cancellation_handle = std::make_unique<std::shared_ptr<NativeCancellation>>(job->cancellation);
  if (napi_create_promise(env, &job->deferred, &promise) != napi_ok ||
      napi_create_string_utf8(env, "sshMcpSshAddProbe", NAPI_AUTO_LENGTH, &resource_name) != napi_ok ||
      napi_create_function(env, "cancel", NAPI_AUTO_LENGTH, CancelAgentReadiness, cancellation_handle.get(), &cancel) != napi_ok) return Unavailable(env);
  if (napi_add_finalizer(env, cancel, cancellation_handle.get(), FinalizeAgentReadinessCancellation, nullptr, nullptr) != napi_ok) return Unavailable(env);
  cancellation_handle.release();
  if (napi_create_object(env, &result) != napi_ok || napi_set_named_property(env, result, "promise", promise) != napi_ok ||
      napi_set_named_property(env, result, "cancel", cancel) != napi_ok) return Unavailable(env);
  if (napi_create_async_work(env, nullptr, resource_name, ExecuteSshAddProbe, CompleteSshAddProbe, job.get(), &job->work) != napi_ok) return Unavailable(env);
  if (napi_queue_async_work(env, job->work) != napi_ok) {
    napi_delete_async_work(env, job->work);
    job->work = nullptr;
    return Unavailable(env);
  }
  job.release();
  return result;
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

bool HasUsableCredentialBlob(const CREDENTIALW* credential) {
  if (credential == nullptr || credential->CredentialBlob == nullptr || credential->CredentialBlobSize == 0 ||
      credential->CredentialBlobSize > 4096 || (credential->CredentialBlobSize % sizeof(wchar_t)) != 0) {
    return false;
  }
  const auto* units = reinterpret_cast<const wchar_t*>(credential->CredentialBlob);
  const size_t length = credential->CredentialBlobSize / sizeof(wchar_t);
  for (size_t index = 0; index < length; ++index) {
    if (units[index] == L'\0') return false;
  }
  return true;
}

napi_value ReadCredential(napi_env env, napi_callback_info info) {
  std::string locator;
  if (!ReadCredentialLocator(env, info, &locator)) return Unavailable(env);
  std::wstring target = kCredentialTargetPrefix + std::wstring(locator.begin(), locator.end());
  PCREDENTIALW credential = nullptr;
  if (!CredReadW(target.c_str(), CRED_TYPE_GENERIC, 0, &credential) || !HasUsableCredentialBlob(credential)) {
    if (credential != nullptr) CredFree(credential);
    return Unavailable(env);
  }
  std::wstring password(reinterpret_cast<wchar_t*>(credential->CredentialBlob), credential->CredentialBlobSize / sizeof(wchar_t));
  CredFree(credential);
  napi_value result{};
  const napi_status status = napi_create_string_utf16(env, reinterpret_cast<const char16_t*>(password.data()), password.size(), &result);
  std::fill(password.begin(), password.end(), L'\0');
  return status == napi_ok ? result : Unavailable(env);
}

// Credential Manager does not offer metadata-only lookup. This intentionally
// observes only whether its non-secret structure is usable, then releases it
// immediately without copying, converting, or returning its blob.
napi_value CredentialAvailable(napi_env env, napi_callback_info info) {
  std::string locator;
  if (!ReadCredentialLocator(env, info, &locator)) return Unavailable(env);
  const std::wstring target = kCredentialTargetPrefix + std::wstring(locator.begin(), locator.end());
  PCREDENTIALW credential = nullptr;
  const bool available = CredReadW(target.c_str(), CRED_TYPE_GENERIC, 0, &credential) != 0 && HasUsableCredentialBlob(credential);
  if (credential != nullptr) CredFree(credential);
  napi_value result{};
  return napi_get_boolean(env, available, &result) == napi_ok ? result : Unavailable(env);
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

napi_value TestBlockDeferredReaper(napi_env env, napi_callback_info info) {
  size_t count = 0;
  if (napi_get_cb_info(env, info, &count, nullptr, nullptr, nullptr) != napi_ok || count != 0) return Unavailable(env);
  if (g_test_deferred_reaper_gate != nullptr) CloseHandle(g_test_deferred_reaper_gate);
  if (g_test_master_started_gate != nullptr) CloseHandle(g_test_master_started_gate);
  g_test_deferred_reaper_gate = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  g_test_master_started_gate = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  g_test_deferred_reaper_completed = false;
  g_test_deferred_reaper_completion = nullptr;
  g_test_force_master_reap_timeout.store(g_test_deferred_reaper_gate != nullptr && g_test_master_started_gate != nullptr);
  napi_value result{};
  return g_test_force_master_reap_timeout.load() && napi_get_undefined(env, &result) == napi_ok ? result : Unavailable(env);
}

napi_value TestReleaseDeferredReaper(napi_env env, napi_callback_info info) {
  size_t count = 0;
  if (napi_get_cb_info(env, info, &count, nullptr, nullptr, nullptr) != napi_ok || count != 0 || g_test_deferred_reaper_gate == nullptr || !SetEvent(g_test_deferred_reaper_gate)) return Unavailable(env);
  g_test_force_master_reap_timeout.store(false);
  napi_value result{};
  return napi_get_undefined(env, &result) == napi_ok ? result : Unavailable(env);
}

napi_value TestWaitForMasterStarted(napi_env env, napi_callback_info info) {
  size_t count = 1;
  napi_value argument{};
  int32_t timeout = 0;
  if (napi_get_cb_info(env, info, &count, &argument, nullptr, nullptr) != napi_ok || count != 1 ||
      napi_get_value_int32(env, argument, &timeout) != napi_ok || timeout <= 0 || timeout > 5000 || g_test_master_started_gate == nullptr) return Unavailable(env);
  napi_value result{};
  return napi_get_boolean(env, WaitForSingleObject(g_test_master_started_gate, static_cast<DWORD>(timeout)) == WAIT_OBJECT_0, &result) == napi_ok ? result : Unavailable(env);
}

napi_value TestDeferredReaperCompletion(napi_env env, napi_callback_info info) {
  size_t count = 0;
  if (napi_get_cb_info(env, info, &count, nullptr, nullptr, nullptr) != napi_ok || count != 0 || g_test_deferred_reaper_completion != nullptr) return Unavailable(env);
  napi_value promise{};
  napi_deferred deferred{};
  if (napi_create_promise(env, &deferred, &promise) != napi_ok) return Unavailable(env);
  if (g_test_deferred_reaper_completed) {
    napi_value result{};
    if (napi_get_undefined(env, &result) != napi_ok || napi_resolve_deferred(env, deferred, result) != napi_ok) return Unavailable(env);
    return promise;
  }
  g_test_deferred_reaper_completion = deferred;
  return promise;
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
    {"provisionApprovedProfile", nullptr, ProvisionApprovedProfile, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"inspectReadiness", nullptr, InspectReadiness, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"readKnownHosts", nullptr, ReadKnownHosts, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"captureKnownHostsSnapshot", nullptr, CaptureKnownHostsSnapshot, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"disposeKnownHostsSnapshot", nullptr, DisposeKnownHostsSnapshot, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"isKnownHostsSnapshotBusy", nullptr, IsKnownHostsSnapshotBusy, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"prepareAgentKeyReadiness", nullptr, PrepareAgentKeyReadiness, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"startAgentKeyReadiness", nullptr, StartNativeAgentKeyReadiness, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"resolveOpenSsh", nullptr, ResolveOpenSsh, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"probeSshAdd", nullptr, ProbeSshAdd, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"startSshAddProbe", nullptr, StartSshAddProbe, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"readCredential", nullptr, ReadCredential, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"credentialAvailable", nullptr, CredentialAvailable, nullptr, nullptr, nullptr, napi_default, nullptr},
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
    {"testBlockDeferredReaper", nullptr, TestBlockDeferredReaper, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"testReleaseDeferredReaper", nullptr, TestReleaseDeferredReaper, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"testWaitForMasterStarted", nullptr, TestWaitForMasterStarted, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"testDeferredReaperCompletion", nullptr, TestDeferredReaperCompletion, nullptr, nullptr, nullptr, napi_default, nullptr},
#endif
  };
  if (napi_define_properties(env, exports, sizeof(properties) / sizeof(properties[0]), properties) != napi_ok) return nullptr;
  return exports;
}
