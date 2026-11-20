{
  "targets": [
    {
      "target_name": "tree_sitter_stellar_toml_binding",
      "dependencies": ["<!(node -p \"require('node-addon-api').targets\"):node_addon_api_except"],
      "include_dirs": [
        "<!@(node -p \"require('node-addon-api').include\")",
        "src"
      ],
      "sources": ["bindings/node/binding.cc", "src/parser.c", "src/scanner.c"],
      "cflags_c": ["-std=c11"]
    }
  ]
}
