#include <windows.h>
#include <bcrypt.h>
#include <sddl.h>
#include <userenv.h>

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

namespace {

constexpr size_t kMaxFrameBytes = 64 * 1024;
constexpr DWORD kApprovalTimeoutMs = 60 * 1000;

std::string Hex(const std::vector<BYTE>& bytes) {
  static constexpr char digits[] = "0123456789abcdef";
  std::string output;
  output.reserve(bytes.size() * 2);
  for (BYTE byte : bytes) {
    output.push_back(digits[byte >> 4]);
    output.push_back(digits[byte & 0x0f]);
  }
  return output;
}

bool DecodeHex(const std::string& value, std::vector<BYTE>* output) {
  if (output == nullptr || value.size() != 64) return false;
  output->clear();
  output->reserve(32);
  for (size_t index = 0; index < value.size(); index += 2) {
    auto digit = [](char value) -> int {
      if (value >= '0' && value <= '9') return value - '0';
      if (value >= 'a' && value <= 'f') return value - 'a' + 10;
      return -1;
    };
    const int high = digit(value[index]);
    const int low = digit(value[index + 1]);
    if (high < 0 || low < 0) return false;
    output->push_back(static_cast<BYTE>((high << 4) | low));
  }
  return true;
}

bool Hmac(const std::vector<BYTE>& key, const std::string& input, std::string* output) {
  BCRYPT_ALG_HANDLE algorithm = nullptr;
  BCRYPT_HASH_HANDLE hash = nullptr;
  DWORD object_bytes = 0;
  DWORD result_bytes = 0;
  if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0 ||
      BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_bytes), sizeof(object_bytes), &result_bytes, 0) != 0) {
    if (algorithm != nullptr) BCryptCloseAlgorithmProvider(algorithm, 0);
    return false;
  }
  std::vector<BYTE> object(object_bytes);
  std::vector<BYTE> digest(32);
  const NTSTATUS created = BCryptCreateHash(algorithm, &hash, object.data(), static_cast<ULONG>(object.size()), const_cast<PUCHAR>(key.data()),
                                            static_cast<ULONG>(key.size()), 0);
  const bool valid = created == 0 && BCryptHashData(hash, const_cast<PUCHAR>(reinterpret_cast<const UCHAR*>(input.data())), static_cast<ULONG>(input.size()), 0) == 0 &&
                     BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) == 0;
  if (hash != nullptr) BCryptDestroyHash(hash);
  BCryptCloseAlgorithmProvider(algorithm, 0);
  if (!valid) return false;
  *output = Hex(digest);
  return true;
}

std::string JsonField(const std::string& json, const char* name) {
  const std::string prefix = std::string("\"") + name + "\":\"";
  const size_t start = json.find(prefix);
  if (start == std::string::npos) return {};
  const size_t value_start = start + prefix.size();
  const size_t end = json.find('"', value_start);
  if (end == std::string::npos) return {};
  return json.substr(value_start, end - value_start);
}

bool WriteExact(HANDLE handle, const void* data, DWORD size) {
  const auto* bytes = static_cast<const BYTE*>(data);
  DWORD written = 0;
  return WriteFile(handle, bytes, size, &written, nullptr) != FALSE && written == size;
}

bool ReadExact(HANDLE handle, void* data, DWORD size, DWORD timeout_ms) {
  auto* bytes = static_cast<BYTE*>(data);
  DWORD read = 0;
  const ULONGLONG deadline = GetTickCount64() + timeout_ms;
  while (read < size) {
    DWORD available = 0;
    if (!PeekNamedPipe(handle, nullptr, 0, nullptr, &available, nullptr)) return false;
    if (available == 0) {
      if (GetTickCount64() >= deadline) return false;
      Sleep(10);
      continue;
    }
    DWORD chunk = 0;
    if (!ReadFile(handle, bytes + read, std::min<DWORD>(available, size - read), &chunk, nullptr) || chunk == 0) return false;
    read += chunk;
  }
  return true;
}

bool ReadFrame(HANDLE handle, std::string* output) {
  BYTE header[4]{};
  if (!ReadExact(handle, header, sizeof(header), kApprovalTimeoutMs)) return false;
  const uint32_t length = (static_cast<uint32_t>(header[0]) << 24) | (static_cast<uint32_t>(header[1]) << 16) |
                          (static_cast<uint32_t>(header[2]) << 8) | header[3];
  if (length == 0 || length > kMaxFrameBytes) return false;
  output->resize(length);
  return ReadExact(handle, output->data(), length, kApprovalTimeoutMs);
}

bool WriteFrame(HANDLE handle, const std::string& value) {
  if (value.empty() || value.size() > kMaxFrameBytes) return false;
  BYTE header[4]{static_cast<BYTE>(value.size() >> 24), static_cast<BYTE>(value.size() >> 16), static_cast<BYTE>(value.size() >> 8),
                 static_cast<BYTE>(value.size())};
  return WriteExact(handle, header, sizeof(header)) && WriteExact(handle, value.data(), static_cast<DWORD>(value.size()));
}

bool CurrentSid(std::vector<BYTE>* sid) {
  HANDLE token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
  DWORD bytes = 0;
  GetTokenInformation(token, TokenUser, nullptr, 0, &bytes);
  if (bytes == 0) {
    CloseHandle(token);
    return false;
  }
  std::vector<BYTE> buffer(bytes);
  const bool read = GetTokenInformation(token, TokenUser, buffer.data(), bytes, &bytes) != FALSE;
  CloseHandle(token);
  if (!read) return false;
  const auto* user = reinterpret_cast<const TOKEN_USER*>(buffer.data());
  sid->assign(static_cast<const BYTE*>(user->User.Sid), static_cast<const BYTE*>(user->User.Sid) + GetLengthSid(user->User.Sid));
  return true;
}

bool ClientBelongsToCurrentUser(HANDLE pipe, const std::vector<BYTE>& expected_sid) {
  ULONG pid = 0;
  if (!GetNamedPipeClientProcessId(pipe, &pid) || pid == 0) return false;
  HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  if (process == nullptr) return false;
  wchar_t image_path[32768]{};
  DWORD image_length = static_cast<DWORD>(sizeof(image_path) / sizeof(image_path[0]));
  if (!QueryFullProcessImageNameW(process, 0, image_path, &image_length)) {
    CloseHandle(process);
    return false;
  }
  const wchar_t* image_name = wcsrchr(image_path, L'\\');
  image_name = image_name == nullptr ? image_path : image_name + 1;
  if (_wcsicmp(image_name, L"node.exe") != 0 && _wcsicmp(image_name, L"ssh-mcp-server.exe") != 0) {
    CloseHandle(process);
    return false;
  }
  HANDLE token = nullptr;
  const bool opened = OpenProcessToken(process, TOKEN_QUERY, &token) != FALSE;
  CloseHandle(process);
  if (!opened) return false;
  DWORD bytes = 0;
  GetTokenInformation(token, TokenUser, nullptr, 0, &bytes);
  std::vector<BYTE> buffer(bytes);
  const bool read = bytes != 0 && GetTokenInformation(token, TokenUser, buffer.data(), bytes, &bytes) != FALSE;
  CloseHandle(token);
  if (!read) return false;
  const auto* user = reinterpret_cast<const TOKEN_USER*>(buffer.data());
  PSID expected = reinterpret_cast<PSID>(const_cast<BYTE*>(expected_sid.data()));
  return EqualSid(user->User.Sid, expected) != FALSE;
}

std::wstring PipeName() {
  const char* configured = std::getenv("SSH_MCP_APPROVER_PIPE");
  if (configured != nullptr && configured[0] != '\0') {
    int length = MultiByteToWideChar(CP_UTF8, 0, configured, -1, nullptr, 0);
    std::wstring value(length > 0 ? length : 0, L'\0');
    if (length > 0) {
      MultiByteToWideChar(CP_UTF8, 0, configured, -1, value.data(), length);
      value.pop_back();
    }
    if (value.rfind(L"\\\\.\\pipe\\", 0) == 0) return value;
  }
  return L"\\\\.\\pipe\\ssh-mcp-approver";
}

std::wstring PromptText(const std::string& command) {
  int length = MultiByteToWideChar(CP_UTF8, 0, command.c_str(), -1, nullptr, 0);
  std::wstring value(length > 0 ? length : 0, L'\0');
  if (length > 0) {
    MultiByteToWideChar(CP_UTF8, 0, command.c_str(), -1, value.data(), length);
    value.pop_back();
  }
  if (value.size() > 512) value.resize(512);
  return L"Allow one approved SSH sudo command?\n\n" + value;
}

int Run() {
  std::vector<BYTE> sid;
  std::vector<BYTE> secret;
  const char* secret_text = std::getenv("SSH_MCP_APPROVER_SECRET");
  if (!CurrentSid(&sid) || secret_text == nullptr || !DecodeHex(secret_text, &secret)) return 2;
  const std::wstring pipe_name = PipeName();
  std::wstring sid_text;
  LPWSTR raw_sid = nullptr;
  if (!ConvertSidToStringSidW(reinterpret_cast<PSID>(sid.data()), &raw_sid)) return 2;
  sid_text.assign(raw_sid);
  LocalFree(raw_sid);
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  const std::wstring sddl = L"D:P(A;;GA;;;" + sid_text + L")";
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr)) return 2;
  SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor, FALSE};
  HANDLE pipe = CreateNamedPipeW(pipe_name.c_str(), PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, 64 * 1024, 64 * 1024,
                                 kApprovalTimeoutMs, &attributes);
  LocalFree(descriptor);
  if (pipe == INVALID_HANDLE_VALUE) return 2;
  const bool connected = ConnectNamedPipe(pipe, nullptr) != FALSE || GetLastError() == ERROR_PIPE_CONNECTED;
  if (!connected || !ClientBelongsToCurrentUser(pipe, sid)) {
    DisconnectNamedPipe(pipe);
    CloseHandle(pipe);
    return 3;
  }
  std::string request;
  const bool received = ReadFrame(pipe, &request);
  const std::string nonce = JsonField(request, "nonce");
  const std::string digest = JsonField(request, "requestDigest");
  const std::string operation = JsonField(request, "operationId");
  const std::string lease = JsonField(request, "leaseIdentityDigest");
  const std::string supplied_mac = JsonField(request, "requestMac");
  const std::string payload = std::string("ssh-mcp-approver/native-request/v1") + '\0' + "[\"" + nonce + "\",\"" + digest + "\",\"" + operation + "\",\"" + lease + "\"]";
  std::string expected_mac;
  const bool authenticated = received && !nonce.empty() && !digest.empty() && !operation.empty() && !lease.empty() && Hmac(secret, payload, &expected_mac) && supplied_mac == expected_mac;
  bool approved = false;
  if (authenticated) approved = MessageBoxW(nullptr, PromptText(JsonField(request, "command")).c_str(), L"ssh-mcp-approver", MB_YESNO | MB_ICONWARNING | MB_SYSTEMMODAL) == IDYES;
  const std::string response_payload = std::string("ssh-mcp-approver/native-response/v1") + '\0' + "[\"" + nonce + "\",\"" + digest + "\"," + (approved ? "true" : "false") + "]";
  std::string response_mac;
  if (!Hmac(secret, response_payload, &response_mac)) response_mac.clear();
  const std::string response = "{\"version\":1,\"type\":\"approval-response\",\"nonce\":\"" + nonce + "\",\"requestDigest\":\"" + digest +
                               "\",\"approved\":" + (approved ? "true" : "false") + ",\"responseMac\":\"" + response_mac + "\"}";
  const bool written = authenticated && !response_mac.empty() && WriteFrame(pipe, response);
  FlushFileBuffers(pipe);
  DisconnectNamedPipe(pipe);
  CloseHandle(pipe);
  return written ? 0 : 4;
}

}  // namespace

int main() {
  return Run();
}
