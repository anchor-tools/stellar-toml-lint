#include <napi.h>

typedef struct TSLanguage TSLanguage;

extern "C" TSLanguage *tree_sitter_stellar_toml();

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  exports["name"] = Napi::String::New(env, "stellar_toml");
  exports["language"] = Napi::External<TSLanguage>::New(
    env, tree_sitter_stellar_toml()
  );
  return exports;
}

NODE_API_MODULE(tree_sitter_stellar_toml_binding, Init)
