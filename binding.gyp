{
  "targets": [
    {
      "target_name": "windows_trust",
      "conditions": [["OS=='win'", {
        "sources": ["native/windows_trust.cc"],
        "libraries": ["-lwintrust", "-lcrypt32", "-ladvapi32", "-lversion", "-lbcrypt", "-lshell32"],
        "defines": ["WIN32_LEAN_AND_MEAN"]
      }]]
    },
    {
      "target_name": "windows_trust_test",
      "conditions": [["OS=='win'", {
        "sources": ["native/windows_trust.cc"],
        "libraries": ["-lwintrust", "-lcrypt32", "-ladvapi32", "-lversion", "-lbcrypt", "-lshell32"],
        "defines": ["WIN32_LEAN_AND_MEAN", "SSH_MCP_NATIVE_TEST=1"]
      }]]
    },
    {
      "target_name": "ssh-mcp-approver",
      "type": "none",
      "conditions": [["OS=='win'", {
        "type": "executable",
        "sources": ["native/windows_approver.cc"],
        "libraries": ["-ladvapi32", "-lbcrypt", "-luser32"],
        "defines": ["WIN32_LEAN_AND_MEAN", "UNICODE", "_UNICODE"]
      }]]
    },
    {
      "target_name": "posix_peer_credentials",
      "conditions": [["OS!='win'", {
        "sources": ["native/posix_peer_credentials.cc"]
      }]]
    }
  ]
}
