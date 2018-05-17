#include "utils.h"

std::string DumpToHexString(const uint8_t* dump, uint32_t dumpsize)
{
    std::string res;
    const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < dumpsize; ++i)
    {
        unsigned char c = static_cast<unsigned char>(dump[i]);
        res += hex[c >> 4];
        res += hex[c & 0xf];
    }
    return res;
}

std::string DumpToHexString(const std::string& dump)
{
    return DumpToHexString((const uint8_t*)dump.data(), (uint32_t)dump.size());
}

void HexStringToDump(const std::string& hexstr, std::vector<uint8_t>& dump)
{
    uint8_t c;
    const char* pos = hexstr.c_str();
    for(size_t i = 0; i < hexstr.size() / 2; ++i)
    {
        sscanf(pos, "%2hhx", &c);
        pos += 2;
        dump.push_back(c);
    }
}

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

#include <openssl/ripemd.h>

bool MhcPubkeyToAddress(uint8_t* in,
                        size_t insize,
                        uint8_t* out,
                        size_t outsize)
{
    if (insize != PUBKEY_LENGTH || outsize != ADDRESS_LENGTH)
        return false;
    else
    {
        uint8_t sha256hash[SHA256_DIGEST_LENGTH] = {0};
        uint8_t finalhash[SHA256_DIGEST_LENGTH] = {0};
        SHA256_CTX sha256_firstpass, sha256_secondpass, sha256_thirdpass;
        //Подсчитываем первый sha256-хэш.
        SHA256_Init(&sha256_firstpass);
        SHA256_Update(&sha256_firstpass, in, insize);
        SHA256_Final(sha256hash, &sha256_firstpass);
        //Сетевой байт
        out[0] = 0;
        //RIPEMD160-хэш от предыдущего
        RIPEMD160_CTX ripemd160;
        RIPEMD160_Init(&ripemd160);
        RIPEMD160_Update(&ripemd160, sha256hash, SHA256_DIGEST_LENGTH);
        RIPEMD160_Final(&out[1], &ripemd160);
        //Хэш от RIPEMD-хэша + заголовочный байт
        SHA256_Init(&sha256_secondpass);
        SHA256_Update(&sha256_secondpass, out, 20 + 1);
        SHA256_Final(sha256hash, &sha256_secondpass);
        //sha256 от последнего хэша
        SHA256_Init(&sha256_thirdpass);
        SHA256_Update(&sha256_thirdpass, sha256hash, SHA256_DIGEST_LENGTH);
        SHA256_Final(finalhash, &sha256_thirdpass);

        //Сохраняем чек-сумму
        out[21] = finalhash[0];
        out[22] = finalhash[1];
        out[23] = finalhash[2];
        out[24] = finalhash[3];
        return true;
    }
}

bool EVPKEYToAddress(EVP_PKEY* pubkey,
                        uint8_t* out,
                        size_t outsize)
{
    bool result = false;
    if (pubkey && out && outsize == ADDRESS_LENGTH)
    {
        unsigned char* data = NULL;
        int datasize = i2d_PUBKEY(pubkey, &data);
        if (datasize >= PUBKEY_LENGTH)
        {
            data[datasize - PUBKEY_LENGTH] = 0x04;
            result = MhcPubkeyToAddress(data + (datasize - PUBKEY_LENGTH), PUBKEY_LENGTH, out, outsize);
        }
        if (data)
            delete[] data;
    }
    return result;
}
