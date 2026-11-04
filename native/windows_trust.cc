#include <node_api.h>

#include <windows.h>
#include <aclapi.h>
#include <sddl.h>

#include <string>
#include <cstring>
#include <vector>

namespace {

constexpr wchar_t kConfigurationKey[] = L"Software\\Vissoto\\ssh-mcp-server";
constexpr wchar_t kStateFile[] = L"connection-profiles.json";
constexpr DWORD kMaxFileBytes = 1024 * 1024;

class Handle final {
 public:
  explicit Handle(HANDLE value = INVALID_HANDLE_VALUE) : value_(value) {}
  ~Handle() { if (value_ != INVALID_HANDLE_VALUE) CloseHandle(value_); }
  Handle(const Handle&) = delete;
  Handle& operator=(const Handle&) = delete;
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

}  // namespace

NAPI_MODULE_INIT() {
  napi_property_descriptor properties[] = {
    {"readProfileState", nullptr, ReadProfileState, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"readKnownHosts", nullptr, ReadKnownHosts, nullptr, nullptr, nullptr, napi_default, nullptr},
  };
  if (napi_define_properties(env, exports, sizeof(properties) / sizeof(properties[0]), properties) != napi_ok) return nullptr;
  return exports;
}
