#include <sys/types.h>
#include <sys/stat.h>

#include "../../utils.h"

#ifndef ADDR_FROM_PUBKEY_FUNCTION
#define ADDR_FROM_PUBKEY_FUNCTION

extern std::ofstream g_errorlog;

void address_from_pubkey(const v8::FunctionCallbackInfo<v8::Value>& args)
{
    std::string hexaddress = "";
    if (args.Length() != 1)
    {
        g_errorlog << "Invalid arguments(" << __FUNCTION__ << ")" << std::endl;
        return;
    }

    v8::Isolate* isolate = args.GetIsolate();
    v8::TryCatch try_catch(isolate);
    v8::HandleScope scope(isolate);
    v8::Local<v8::Value> arg0 = args[0];
    if (arg0->IsString())
    {
        v8::String::Utf8Value param0(arg0->ToString());
        std::string hex_pubkey = *param0;
        std::vector<uint8_t> pubkey;
        HexStringToDump(hex_pubkey, pubkey);

        //Обрабатываем ключ
        EVP_PKEY* pk = ParseDER(pubkey.data(), pubkey.size());
        if (pk)
        {
            char address[ADDRESS_LENGTH] = {0};
            if (EVPKEYToAddress(pk, (uint8_t*)address, ADDRESS_LENGTH))
            {
                hexaddress = "0x" + DumpToHexString((const uint8_t*)address, ADDRESS_LENGTH);
            }
            else
                g_errorlog << "Public key to address conversion error(" <<  __FUNCTION__ << ")" << std::endl;

            EVP_PKEY_free(pk);
        }
        else
            g_errorlog << "Public key format error(" <<  __FUNCTION__ << ")" << std::endl;
    }
    else
        g_errorlog << "Invalid argument type(" << __FUNCTION__ << ")" << std::endl;

    args.GetReturnValue().Set(v8::String::NewFromUtf8(isolate, hexaddress.c_str()));
}

void AddAddressFromPubkey(v8::Local<v8::ObjectTemplate>* global, v8::Isolate* isolate)
{
    v8::Local<v8::FunctionTemplate> address_from_pubkeyfunc = v8::FunctionTemplate::New(isolate, address_from_pubkey);
    (*global)->Set(v8::String::NewFromUtf8(isolate, "meta_MHC_addr_from_pub_key"), address_from_pubkeyfunc);
}

#endif
