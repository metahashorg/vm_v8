#include <openssl/opensslconf.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/x509v3.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "../../utils.h"

#ifndef CHECK_SIGN_FUNCTION
#define CHECK_SIGN_FUNCTION

void check_sign(const v8::FunctionCallbackInfo<v8::Value>& args)
{
    bool result = false;
    if (args.Length() < 3)
        return;

    v8::Isolate* isolate = args.GetIsolate();
    v8::TryCatch try_catch(isolate);
    v8::HandleScope scope(isolate);
    v8::Local<v8::Value> arg0 = args[0];
    v8::Local<v8::Value> arg1 = args[1];
    v8::Local<v8::Value> arg2 = args[2];
    if (arg0->IsString() && arg1->IsString() && arg2->IsString())
    {
        v8::String::Utf8Value param0(arg0->ToString());
        v8::String::Utf8Value param1(arg1->ToString());
        v8::String::Utf8Value param2(arg2->ToString());
        std::string hex_pubkey = *param0;
        std::string hex_sign = *param1;
        std::string data = *param2;

        std::vector<uint8_t> pubkey;
        std::vector<uint8_t> sign;
        HexStringToDump(hex_pubkey, pubkey);
        HexStringToDump(hex_sign, sign);

        //Обрабатываем ключ
        EVP_PKEY* pk = ParseDER(pubkey.data(), pubkey.size());
        if (pk)
        {
            //Восстанавливаем сигнатуру
            ECDSA_SIG* signature = ECSignatureFromBuffer(sign.data(), sign.size(), pk);
            if (signature)
            {
                result = CheckBufferSignature(pk, (const unsigned char*)data.data(), data.size(), signature);
                ECDSA_SIG_free(signature);
            }
            EVP_PKEY_free(pk);
        }

    }

    args.GetReturnValue().Set(v8::Boolean::New(isolate, result));
}

void AddCheckSign(v8::Local<v8::ObjectTemplate>* global, v8::Isolate* isolate)
{
    v8::Local<v8::FunctionTemplate> check_signfunc = v8::FunctionTemplate::New(isolate, check_sign);
    (*global)->Set(v8::String::NewFromUtf8(isolate, "meta_MHC_check_sign"), check_signfunc);
}

#endif
