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

#include "../../utils.h"

#ifndef CHECK_SIGN_FUNCTION
#define CHECK_SIGN_FUNCTION

EVP_PKEY* ParseDER(unsigned char* binary, size_t binarysize)
{
    bool result = false;
    EVP_PKEY* key = NULL;
    if (binary && binarysize != 0)
    {
        key = EVP_PKEY_new();
        if (key)
        {
            if (d2i_PUBKEY(&key, (const unsigned char**)&binary, binarysize))
                result = true;
            else
                printf("%s: i2d_PUBKEY error.\n", __FUNCTION__);
        }
    }
    else
        printf("%s: Invalid parameters.\n", __FUNCTION__);

    if (result)
        return key;
    else
    {
        EVP_PKEY_free(key);
        return NULL;
    }
}

ECDSA_SIG* ECSignatureFromBuffer(unsigned char* buff, size_t bufsize, EVP_PKEY* key)
{
    EC_KEY* eckey = EVP_PKEY_get1_EC_KEY(key);
    unsigned int degree = EC_GROUP_get_degree(EC_KEY_get0_group(eckey));
    unsigned int bn_len = (degree + 7) / 8;
    ECDSA_SIG* signature = ECDSA_SIG_new();
    BIGNUM* r = BN_bin2bn(buff, bn_len, NULL);
    BIGNUM* s = BN_bin2bn(buff + bn_len, bn_len, NULL);
    if (r && s)
    {
        ECDSA_SIG_set0(signature, r, s);
        return signature;
    }
    return NULL;
}

bool CheckBufferSignature(EVP_PKEY* publicKey, const unsigned char* buf, size_t bufsize, ECDSA_SIG* signature)
{
    if (publicKey && buf && bufsize != 0 && signature)
    {
        EVP_MD_CTX *mdctx;
        unsigned char md_value[EVP_MAX_MD_SIZE];
        unsigned int md_len;

        mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
        EVP_DigestUpdate(mdctx, buf, bufsize);
        EVP_DigestFinal_ex(mdctx, md_value, &md_len);
        EVP_MD_CTX_free(mdctx);

        return (ECDSA_do_verify(md_value, md_len, signature, EVP_PKEY_get1_EC_KEY(publicKey)) == 1);
	}
	else
        return false;
}

void check_sign(const v8::FunctionCallbackInfo<v8::Value>& args)
{
    std::string hs = "";
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
                if (CheckBufferSignature(pk, (const unsigned char*)data.data(), data.size(), signature))
                    printf("Verified OK.\n");
                else
                    printf("Not valid.\n");
            }
        }

    }

    //args.GetReturnValue().Set(v8::String::NewFromUtf8(isolate, hs.c_str()));
}

void AddCheckSign(v8::Local<v8::ObjectTemplate>* global, v8::Isolate* isolate)
{
    v8::Local<v8::FunctionTemplate> check_signfunc = v8::FunctionTemplate::New(isolate, check_sign);
    (*global)->Set(v8::String::NewFromUtf8(isolate, "meta_MHC_check_sign"), check_signfunc);
}

#endif
