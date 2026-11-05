#include <node_api.h>

#include <windows.h>
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
#include <cstring>
#include <vector>

namespace {

constexpr wchar_t kConfigurationKey[] = L"Software\\Vissoto\\ssh-mcp-server";
constexpr wchar_t kStateFile[] = L"connection-profiles.json";
constexpr DWORD kMaxFileBytes = 1024 * 1024;
constexpr wchar_t kCredentialTargetPrefix[] = L"Vissoto/ssh-mcp-server/";

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

bool TrustedOpenSsh(std::wstring* ssh, std::wstring* ssh_add, std::array<DWORD, 4>* version, Handle* retained_system = nullptr, Handle* retained_directory = nullptr, Handle* retained_ssh_add = nullptr) {
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
  Handle root_handle(CreateFileW(root.c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
  if (root_handle.get() == INVALID_HANDLE_VALUE || !VerifyFile(root_handle.get(), operator_sid, true)) return false;
  const std::wstring path = root + L"\\" + leaf;
  Handle file_handle(CreateFileW(path.c_str(), GENERIC_READ | FILE_READ_ATTRIBUTES | READ_CONTROL, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
  if (file_handle.get() == INVALID_HANDLE_VALUE || !VerifyFile(file_handle.get(), operator_sid, false)) return false;
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
  std::wstring ssh; std::wstring ssh_add; std::array<DWORD, 4> version{};
  Handle system_handle;
  Handle openssh_handle;
  Handle ssh_add_handle;
  if (!TrustedOpenSsh(&ssh, &ssh_add, &version, &system_handle, &openssh_handle, &ssh_add_handle)) return Unavailable(env);
  std::wstring command = L"\"" + ssh_add + L"\" -l";
  DWORD exit_code = 1;
  if (LaunchHiddenProcess(ssh_add, std::move(command), static_cast<DWORD>(timeout), &exit_code) != LaunchResult::kCompleted) return Unavailable(env);
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

napi_value ReplacementRaceResult(napi_env env, bool hook_executed, bool read_succeeded, const char* stage) {
  napi_value result{};
  napi_value hook_value{};
  napi_value read_value{};
  napi_value stage_value{};
  if (napi_create_object(env, &result) != napi_ok || napi_get_boolean(env, hook_executed, &hook_value) != napi_ok || napi_get_boolean(env, read_succeeded, &read_value) != napi_ok || napi_create_string_utf8(env, stage, NAPI_AUTO_LENGTH, &stage_value) != napi_ok || napi_set_named_property(env, result, "hookExecuted", hook_value) != napi_ok || napi_set_named_property(env, result, "readSucceeded", read_value) != napi_ok || napi_set_named_property(env, result, "stage", stage_value) != napi_ok) return Unavailable(env);
  return result;
}

napi_value TestReadReplacementRace(napi_env env, napi_callback_info info) {
  size_t count = 0;
  std::wstring state_root;
  std::wstring known_hosts_root;
  std::vector<BYTE> operator_sid;
  if (napi_get_cb_info(env, info, &count, nullptr, nullptr, nullptr) != napi_ok || count != 0) return Unavailable(env);
  if (!LoadConfiguration(&state_root, &known_hosts_root, &operator_sid)) return ReplacementRaceResult(env, false, false, "configuration");
  Handle root_handle(CreateFileW(state_root.c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
  if (root_handle.get() == INVALID_HANDLE_VALUE || !VerifyFile(root_handle.get(), operator_sid.data(), true)) return ReplacementRaceResult(env, false, false, "root-initial");
  const std::wstring path = state_root + L"\\" + kStateFile;
  Handle file_handle(CreateFileW(path.c_str(), GENERIC_READ | FILE_READ_ATTRIBUTES | READ_CONTROL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
  if (file_handle.get() == INVALID_HANDLE_VALUE || !VerifyFile(file_handle.get(), operator_sid.data(), false)) return ReplacementRaceResult(env, false, false, "file-initial");
  const bool hook_executed = DeleteFileW(path.c_str()) != 0 && MoveFileExW((path + L".replacement").c_str(), path.c_str(), MOVEFILE_WRITE_THROUGH) != 0;
  if (!hook_executed) return ReplacementRaceResult(env, false, false, "replacement");
  Handle root_recheck(CreateFileW(state_root.c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
  Handle file_recheck(CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
  if (root_recheck.get() == INVALID_HANDLE_VALUE) return ReplacementRaceResult(env, true, false, "root-reopen");
  if (file_recheck.get() == INVALID_HANDLE_VALUE) return ReplacementRaceResult(env, true, false, "file-reopen");
  if (!VerifyDirectoryChain(state_root, operator_sid.data())) return ReplacementRaceResult(env, true, false, "directory-recheck");
  if (!VerifyFile(root_recheck.get(), operator_sid.data(), true)) return ReplacementRaceResult(env, true, false, "root-recheck");
  if (!VerifyFile(file_recheck.get(), operator_sid.data(), false)) return ReplacementRaceResult(env, true, false, "file-recheck");
  if (!SameIdentity(root_handle.get(), root_recheck.get())) return ReplacementRaceResult(env, true, false, "root-identity-mismatch");
  if (!SameIdentity(file_handle.get(), file_recheck.get())) return ReplacementRaceResult(env, true, false, "file-identity-mismatch");
  return ReplacementRaceResult(env, true, true, "unexpected-success");
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

napi_value TestUntrustedOpenSshCandidate(napi_env env, napi_callback_info info) {
  std::wstring candidate;
  if (!ReadWideArgument(env, info, &candidate)) return Unavailable(env);
  Handle handle;
  std::array<DWORD, 4> version{};
  const bool expected_path = IsExpectedOpenSshExecutable(candidate);
  const bool trusted_object = OpenTrustedSystemObject(candidate, false, &handle);
  const bool microsoft_signed = IsMicrosoftSigned(candidate);
  const bool supported_version = IsSupportedOpenSshVersion(candidate, &version);
  napi_value result{};
  napi_value expected_path_value{};
  napi_value trusted_value{};
  napi_value signed_value{};
  napi_value version_value{};
  if (napi_create_object(env, &result) != napi_ok || napi_get_boolean(env, expected_path, &expected_path_value) != napi_ok || napi_get_boolean(env, trusted_object, &trusted_value) != napi_ok || napi_get_boolean(env, microsoft_signed, &signed_value) != napi_ok || napi_get_boolean(env, supported_version, &version_value) != napi_ok || napi_set_named_property(env, result, "expectedOpenSshPath", expected_path_value) != napi_ok || napi_set_named_property(env, result, "trustedObject", trusted_value) != napi_ok || napi_set_named_property(env, result, "microsoftSigned", signed_value) != napi_ok || napi_set_named_property(env, result, "supportedVersion", version_value) != napi_ok) return Unavailable(env);
  return result;
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
    {"resolveOpenSsh", nullptr, ResolveOpenSsh, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"probeSshAdd", nullptr, ProbeSshAdd, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"readCredential", nullptr, ReadCredential, nullptr, nullptr, nullptr, napi_default, nullptr},
#ifdef SSH_MCP_NATIVE_TEST
    {"testReadReplacementRace", nullptr, TestReadReplacementRace, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"testSystemOwnerMismatch", nullptr, TestSystemOwnerMismatch, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"testUntrustedOpenSshCandidate", nullptr, TestUntrustedOpenSshCandidate, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"testLaunch", nullptr, TestLaunch, nullptr, nullptr, nullptr, napi_default, nullptr},
#endif
  };
  if (napi_define_properties(env, exports, sizeof(properties) / sizeof(properties[0]), properties) != napi_ok) return nullptr;
  return exports;
}
