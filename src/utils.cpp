#include "utils.h"

#include <fstream>
#include <regex>
#include <openssl/ripemd.h>
#include <re2/re2.h>
#include <dirent.h>
#include <sys/stat.h>

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

EVP_PKEY* ParsePubDER(unsigned char* binary, size_t binarysize)
{
    EVP_PKEY* key = NULL;
    if (binary && binarysize != 0)
    {
        if (d2i_PUBKEY(&key, (const unsigned char**)&binary, binarysize))
            return key;
    }
    return NULL;
}

EVP_PKEY* ParsePrivDER(unsigned char* binary, size_t binarysize)
{
    EC_KEY* eckey = NULL;
    EVP_PKEY* key = EVP_PKEY_new();
    if (binary && binarysize != 0)
    {
        if (d2i_ECPrivateKey(&eckey, (const unsigned char**)&binary, binarysize))
        {
            EVP_PKEY_assign_EC_KEY(key, eckey);
            return key;
        }
    }
    return NULL;
}

ECDSA_SIG* ECSignatureFromBuffer(unsigned char* buff, size_t bufsize, EVP_PKEY* key)
{
    ECDSA_SIG* signature = NULL;
    EC_KEY* eckey = EVP_PKEY_get1_EC_KEY(key);
    if (eckey)
    {
        unsigned int degree = EC_GROUP_get_degree(EC_KEY_get0_group(eckey));
        unsigned int bn_len = (degree + 7) / 8;
        EC_KEY_free(eckey);
        BIGNUM* r = BN_bin2bn(buff, bn_len, NULL);
        BIGNUM* s = BN_bin2bn(buff + bn_len, bn_len, NULL);
        if (r && s)
        {
            signature = ECDSA_SIG_new();
            ECDSA_SIG_set0(signature, r, s);
        }
    }
    return signature;
}

void ECSignatureToBuffer(unsigned char** buff, size_t* bufsize, EVP_PKEY* key, ECDSA_SIG* signature)
{
    const BIGNUM* r = NULL;
    const BIGNUM* s = NULL;
    ECDSA_SIG_get0(signature, &r, &s);
    int r_num = BN_num_bytes(r);
    int s_num = BN_num_bytes(s);
    unsigned int degree = EC_GROUP_get_degree(EC_KEY_get0_group(EVP_PKEY_get1_EC_KEY(key)));
    unsigned int bn_len = (degree + 7) / 8;
    unsigned int buf_len = bn_len * 2;
    unsigned char* raw_buf = new unsigned char[buf_len];
    BN_bn2bin(r, raw_buf + bn_len - r_num);
    BN_bn2bin(s, raw_buf + buf_len - s_num);
    *buff = raw_buf;
    *bufsize = buf_len;
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

bool MhcPubkeyToAddress(uint8_t* in,
                        size_t insize,
                        uint8_t* out,
                        size_t outsize,
                        uint8_t netbyte = 0)
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
        out[0] = netbyte;
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

//Создание пары ключей и адреса
bool CreateECKeyPairAndAddr(std::string& privkey,
                            std::string& pubkey,
                            std::string& address,
                            uint8_t netbyte,
                            const char* password)
{
    EC_KEY* myecc  = NULL;
    unsigned char* privkeydata = NULL;
    unsigned char* pubkeydata = NULL;
    int eccgrp;
    bool rslt = false;
    const char* pass = NULL;
    const EVP_CIPHER* cipher = NULL;

    eccgrp = OBJ_txt2nid("prime256v1");
    myecc = EC_KEY_new_by_curve_name(eccgrp);
    EC_KEY_set_asn1_flag(myecc, OPENSSL_EC_NAMED_CURVE);

    if (EC_KEY_generate_key(myecc) > 0)
    {
        if (password)
        {
            pass = password;
            cipher = EVP_aes_128_cbc();
        }
        (void)cipher;
        (void)pass;

        //Сохраняем ключи в двоичной форме
        int pubkeysize = i2d_EC_PUBKEY(myecc, &pubkeydata);
        int privkeysize = i2d_ECPrivateKey(myecc, &privkeydata);
        if (pubkeysize && privkeysize)
        {
            //Переводим в hex
            pubkey = DumpToHexString(pubkeydata, pubkeysize);
            privkey = DumpToHexString(privkeydata, privkeysize);
            //Генерируем адрес
            if (pubkeysize >= 65)
            {
                pubkeydata[pubkeysize - 65] = 0x04;
                uint8_t out[25];
                if (MhcPubkeyToAddress(pubkeydata + (pubkeysize - 65), 65, out, 25, netbyte))
                {
                    address = DumpToHexString(out, 25);
                    rslt = true;
                }
            }
        }
    }

    if (privkeydata)
        delete[] privkeydata;
    if (pubkeydata)
        delete[] pubkeydata;
    EC_KEY_free(myecc);

    return rslt;
}

std::string HexPubkeyToAddress(const std::string& hexpubkey, uint8_t firstbyte)
{
    std::string address = "";
    std::vector<uint8_t> pubkeydump;
    if (!hexpubkey.empty())
    {
        HexStringToDump(hexpubkey, pubkeydump);
        size_t pubkeysize = pubkeydump.size();
        uint8_t* pubkeydata = pubkeydump.data();

        if (pubkeysize >= 65)
        {
            pubkeydata[pubkeysize - 65] = 0x04;
            uint8_t out[25];
            if (MhcPubkeyToAddress(pubkeydata + (pubkeysize - 65), 65, out, 25, firstbyte))
            {
                address = "0x" + DumpToHexString(out, 25);
            }
        }
    }
    return address;
}

bool SignBuffer(EVP_PKEY* privkey, const unsigned char* buf, size_t bufsize, ECDSA_SIG** signature)
{
    if (privkey && buf && bufsize != 0 && signature)
    {
        EVP_MD_CTX* mdctx;
        unsigned char md_value[EVP_MAX_MD_SIZE];
        unsigned int md_len;

        *signature = NULL;
        mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
        EVP_DigestUpdate(mdctx, buf, bufsize);
        EVP_DigestFinal_ex(mdctx, md_value, &md_len);
        EVP_MD_CTX_free(mdctx);

        ECDSA_SIG* sig = ECDSA_do_sign(md_value, md_len, EVP_PKEY_get1_EC_KEY(privkey));
        if (sig)
        {
            *signature = sig;
            return true;
        }
        else
            return false;

	}
	else
        return false;
}

//Функции создания и проверки подписи в стандартной для сервиса форме
std::string SignData(const std::string& data, const std::string& hexprivkey)
{
    std::string signature = "";
    if (!data.empty() && !hexprivkey.empty())
    {
        std::vector<uint8_t> privkey;
        HexStringToDump(hexprivkey, privkey);
        EVP_PKEY* pk = ParsePrivDER(privkey.data(), privkey.size());
        if (pk)
        {
            ECDSA_SIG* sig = NULL;
            if (SignBuffer(pk, (const unsigned char*)data.data(), data.size(), &sig))
            {
                unsigned char* sigdata = NULL;
                size_t sigdatasize = 0;
                ECSignatureToBuffer(&sigdata, &sigdatasize, pk, sig);
                if (sigdata)
                {
                    signature = DumpToHexString((const uint8_t*)sigdata, (uint8_t)sigdatasize);
                    delete[] sigdata;
                }
            }
        }
        EVP_PKEY_free(pk);
    }
    return signature;
}

bool CheckSign(const std::string& data, const std::string& signature, const std::string& pubkey)
{
    EVP_PKEY* pk = NULL;
    ECDSA_SIG* sig = NULL;
    bool rslt = false;
    if (!data.empty() && !signature.empty() && !pubkey.empty())
    {
        std::vector<uint8_t> pubkeydump;
        std::vector<uint8_t> signaturedump;
        HexStringToDump(pubkey, pubkeydump);
        HexStringToDump(signature, signaturedump);
        pk = ParsePubDER(pubkeydump.data(), pubkey.size());
        sig = ECSignatureFromBuffer(signaturedump.data(), signaturedump.size(), pk);
        if (pk && sig)
            rslt = CheckBufferSignature(pk, (const unsigned char*)data.data(), data.size(), sig);
    }
    if (pk)
        EVP_PKEY_free(pk);
    if (sig)
        ECDSA_SIG_free(sig);
    return rslt;
}

std::string ReadFile(const std::string& path)
{
    std::ifstream input(path, std::ifstream::binary);
    std::string str = "";

    if (input)
    {
        input.seekg(0, input.end);
        size_t length = input.tellg();
        input.seekg(0, input.beg);
        str.resize(length, ' ');
        input.read(&*str.begin(), length);
        input.close();
    }
    return str;
}

void ParseBytecode(const std::string& bytecode, std::unordered_map<std::string, size_t>& instructions)
{
    std::string ins = "";
    std::string remainder = "";
    std::string text = bytecode;
    size_t i = 0;
    size_t j = 0;
    i = text.find('@');
    while (i != std::string::npos)
    {
        i += 27;//Указывает на первый байт инструкции.
        j = text.find(' ', i);
        ins = text.substr(i, j-i);

        auto it = instructions.find(ins);
        if (it != instructions.end())
            it->second++;
        else
            instructions[ins] = 1;
        i = text.find('@', j);
    }
}

std::string BytecodeToListing(const std::string& bytecode)
{
    std::string listing = "";
    std::string ins = "";
    std::string remainder = "";
    std::string text = bytecode;
    size_t i = 0;
    size_t j = 0;
    i = text.find('@');
    while (i != std::string::npos)
    {
        i += 27;//Указывает на первый байт инструкции.
        j = text.find(0x0A, i);
        ins = text.substr(i, j-i);
        listing += ins + '\n';
        i = text.find('@', j);
    }
    return listing;
}

void SnapshotEnumerator::Reload(const char* directory)
{
    DIR *dir;
    struct dirent *ent;
    if (!snapshotsnames.empty())
        snapshotsnames.clear();
    if ((dir = opendir (directory)) != NULL)
    {
        while ((ent = readdir(dir)) != NULL)
        {
            std::string filename = ent->d_name;
            size_t i = filename.rfind('.', filename.size());
            if (i != std::string::npos)
            {
                std::string ext = filename.substr(i, filename.size()-i);
                if (ext.compare(".shot") == 0)
                {
                    i = filename.find('.');
                    std::string addr = filename.substr(0, i);
                    auto it = snapshotsnames.find(addr);
                    if (it != snapshotsnames.end())
                        it->second.push_back(filename);
                    else
                    {
                        std::vector<std::string> fn;
                        fn.push_back(filename);
                        snapshotsnames[addr] = fn;
                    }
                }
            }
        }
        closedir(dir);
    }
    FindNewestSnapshots();
}
bool compareFunction (std::string a, std::string b)
{
    size_t i,j;
    std::string anum;
    std::string bnum;
    i = a.find('.');
    if (i != std::string::npos)
    {
        j = a.find('.', i+1);
        anum = a.substr(i+1, j-1-i);

        if (!anum.empty())
        {
            i = b.find('.');
            if (i != std::string::npos)
            {
                j = b.find('.', i+1);
                bnum = b.substr(i+1, j-1-i);
                if (!bnum.empty())
                {
                    if (anum.compare("cmpl") == 0)
                        return true;
                    else
                    {
                        if (bnum.compare("cmpl") == 0)
                            return false;
                        else
                        {
                            int an = std::stoi(anum);
                            int bn = std::stoi(bnum);
                            return (an < bn);
                        }

                    }
                }
            }
        }
    }
    return true;
}


void SnapshotEnumerator::FindNewestSnapshots()
{
    for (auto it = snapshotsnames.begin(); it != snapshotsnames.end(); ++it)
    {
        if (it->second.size() > 1)
            std::sort(it->second.begin(), it->second.end(), compareFunction);
    }
}

std::string GetNextSnapNumber(const std::string& snapfilename)
{
    std::string result = "";
    std::string snapnum;
    size_t i,j;
    i = snapfilename.rfind('.');
    if (i != std::string::npos)
    {
        j = snapfilename.rfind('.', i-1);
        if (j != std::string::npos)
        {
            result = snapfilename.substr(j+1, i-j-1);
            if (result.compare("cmpl") == 0)
                result = "0";
            else
            {
                if (!result.empty())
                {
                    result = std::to_string(std::stoi(result) + 1);
                }
            }
        }
    }
    return result;
}

bool IsDirectoryExist(const char* dir)
{
    bool rslt = false;
    struct stat st;
    if (stat(dir, &st) == 0)
        rslt = (st.st_mode & (S_IFDIR != 0));
    return rslt;
}

void GetProperties(v8::Isolate* isolate,
                const v8::HeapGraphNode* node,
                std::vector<std::vector<std::string>>& symbols)
{
    for (int i = 0, count = node->GetChildrenCount(); i < count; ++i)
    {
        const v8::HeapGraphEdge* prop = node->GetChild(i);
        v8::String::Utf8Value node_name(isolate, prop->GetName());
        symbols[node->GetType()].push_back(*node_name);
    }
}

const v8::HeapGraphNode* GetProperty(v8::Isolate* isolate,
                                            const v8::HeapGraphNode* node,
                                            v8::HeapGraphEdge::Type type,
                                            const char* name)
{
    for (int i = 0, count = node->GetChildrenCount(); i < count; ++i)
    {
        const v8::HeapGraphEdge* prop = node->GetChild(i);
        v8::String::Utf8Value prop_name(isolate, prop->GetName());
        if (prop->GetType() == type && strcmp(name, *prop_name) == 0)
            return prop->GetToNode();
  }
  return NULL;
}
