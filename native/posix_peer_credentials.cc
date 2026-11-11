#include <node_api.h>

#include <cerrno>
#include <cstdint>

#if defined(__APPLE__)
#include <sys/socket.h>
#include <sys/types.h>
#elif defined(__linux__)
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace {

napi_value Unavailable(napi_env env) {
  napi_value message{};
  napi_value error{};
  napi_create_string_utf8(env, "POSIX peer credentials are unavailable", NAPI_AUTO_LENGTH, &message);
  napi_create_error(env, nullptr, message, &error);
  napi_throw(env, error);
  return nullptr;
}

napi_value GetPeerCredentials(napi_env env, napi_callback_info info) {
  size_t count = 1;
  napi_value input{};
  int32_t descriptor = -1;
  if (napi_get_cb_info(env, info, &count, &input, nullptr, nullptr) != napi_ok || count != 1 || napi_get_value_int32(env, input, &descriptor) != napi_ok || descriptor < 0) {
    return Unavailable(env);
  }

  uint32_t uid = 0;
  int32_t pid = 0;
#if defined(__linux__)
  struct ucred credentials{};
  socklen_t length = sizeof(credentials);
  if (getsockopt(descriptor, SOL_SOCKET, SO_PEERCRED, &credentials, &length) != 0 || credentials.uid == static_cast<uid_t>(-1) || credentials.pid <= 0) {
    return Unavailable(env);
  }
  uid = static_cast<uint32_t>(credentials.uid);
  pid = static_cast<int32_t>(credentials.pid);
#elif defined(__APPLE__)
  uid_t peer_uid = 0;
  gid_t peer_gid = 0;
  if (getpeereid(descriptor, &peer_uid, &peer_gid) != 0) return Unavailable(env);
  uid = static_cast<uint32_t>(peer_uid);
#else
  return Unavailable(env);
#endif

  napi_value result{};
  napi_value uid_value{};
  if (napi_create_object(env, &result) != napi_ok || napi_create_uint32(env, uid, &uid_value) != napi_ok || napi_set_named_property(env, result, "uid", uid_value) != napi_ok) {
    return Unavailable(env);
  }
#if defined(__linux__)
  napi_value pid_value{};
  if (napi_create_int32(env, pid, &pid_value) != napi_ok || napi_set_named_property(env, result, "pid", pid_value) != napi_ok) return Unavailable(env);
#endif
  return result;
}

}  // namespace

NAPI_MODULE_INIT() {
  napi_property_descriptor properties[] = {
      {"getPeerCredentials", nullptr, GetPeerCredentials, nullptr, nullptr, nullptr, napi_default, nullptr},
  };
  if (napi_define_properties(env, exports, sizeof(properties) / sizeof(properties[0]), properties) != napi_ok) return nullptr;
  return exports;
}
