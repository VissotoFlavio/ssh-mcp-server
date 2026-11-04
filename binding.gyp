{
  "targets": [
    {
      "target_name": "windows_trust",
      "sources": ["native/windows_trust.cc"],
      "conditions": [["OS=='win'", { "defines": ["WIN32_LEAN_AND_MEAN"] }]]
    }
  ]
}
