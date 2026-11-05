{
  "targets": [
    {
      "target_name": "windows_trust",
      "sources": ["native/windows_trust.cc"],
      "libraries": ["-lwintrust", "-lcrypt32", "-ladvapi32", "-lversion"],
      "conditions": [["OS=='win'", { "defines": ["WIN32_LEAN_AND_MEAN"] }]]
    },
    {
      "target_name": "windows_trust_test",
      "sources": ["native/windows_trust.cc"],
      "libraries": ["-lwintrust", "-lcrypt32", "-ladvapi32", "-lversion"],
      "conditions": [["OS=='win'", { "defines": ["WIN32_LEAN_AND_MEAN", "SSH_MCP_NATIVE_TEST=1"] }]]
    }
  ]
}
