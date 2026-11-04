{
  "targets": [
    {
      "target_name": "windows_trust",
      "sources": ["native/windows_trust.cc"],
      "libraries": ["-lwintrust", "-lcrypt32"],
      "conditions": [["OS=='win'", { "defines": ["WIN32_LEAN_AND_MEAN"] }]]
    }
  ]
}
