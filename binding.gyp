{
  "targets": [
    {
      "target_name": "windows_trust",
      "sources": ["native/windows_trust.cc"],
      "libraries": ["-lwintrust", "-lcrypt32", "-ladvapi32", "-lversion", "-lbcrypt", "-lshell32"],
      "conditions": [["OS=='win'", { "defines": ["WIN32_LEAN_AND_MEAN"] }]]
    },
    {
      "target_name": "windows_trust_test",
      "sources": ["native/windows_trust.cc"],
      "libraries": ["-lwintrust", "-lcrypt32", "-ladvapi32", "-lversion", "-lbcrypt", "-lshell32"],
      "conditions": [["OS=='win'", { "defines": ["WIN32_LEAN_AND_MEAN", "SSH_MCP_NATIVE_TEST=1"] }]]
    },
    {
      "target_name": "ssh-mcp-approver",
      "type": "executable",
      "sources": ["native/windows_approver.cc"],
      "libraries": ["-ladvapi32", "-lbcrypt", "-luser32"],
      "conditions": [["OS=='win'", { "defines": ["WIN32_LEAN_AND_MEAN", "UNICODE", "_UNICODE"] }]]
    }
  ]
}
