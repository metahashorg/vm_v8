#include <openssl/sha.h>
#include "../../utils.h"

#ifndef SHA256_FUNCTION
#define SHA256_FUNCTION

void sha256(const v8::FunctionCallbackInfo<v8::Value>& args)
{
    std::string hs = "";
    if (args.Length() < 1)
        return;

    v8::Isolate* isolate = args.GetIsolate();
    v8::TryCatch try_catch(isolate);
    v8::HandleScope scope(isolate);
    v8::Local<v8::Value> arg = args[0];

    if (arg->IsString())
    {
        v8::String::Utf8Value param1(arg->ToString());
        const char* data = *param1;
        uint8_t sha256hash[SHA256_DIGEST_LENGTH] = {0};
        SHA256_CTX sha256_pass;
        SHA256_Init(&sha256_pass);
        SHA256_Update(&sha256_pass, data, strlen(data));
        SHA256_Final(sha256hash, &sha256_pass);
        hs = DumpToHexString(sha256hash, SHA256_DIGEST_LENGTH);
    }
    args.GetReturnValue().Set(v8::String::NewFromUtf8(isolate, hs.c_str()));
}

void AddSHA256(v8::Local<v8::ObjectTemplate>* global, v8::Isolate* isolate)
{
    v8::Local<v8::FunctionTemplate> sha256func = v8::FunctionTemplate::New(isolate, sha256);
    (*global)->Set(v8::String::NewFromUtf8(isolate, "meta_sha256"), sha256func);
}

#endif
