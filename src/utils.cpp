#include "utils.h"

#include <fstream>
#include <regex>
#include <openssl/ripemd.h>
#include <re2/re2.h>
#include <dirent.h>

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
    EVP_PKEY* key = NULL;
    if (binary && binarysize != 0)
    {
        if (d2i_PUBKEY(&key, (const unsigned char**)&binary, binarysize))
            return key;
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

void SnapshotEnumerator::FindNewestSnapshots()
{
    size_t j, k;
    std::string snum = "";
    for (auto it = snapshotsnames.begin(); it != snapshotsnames.end(); ++it)
    {
        int maxnum = 0;
        size_t maxnumidx = 0;
        if (it->second.size() > 1)
        {
            for (size_t i = 0; i < it->second.size(); ++i)
            {
                j = it->second[i].find('.', 0);
                if (j != std::string::npos)
                {
                    k = it->second[i].find('.', j+1);
                    if (k != std::string::npos)
                    {
                        snum = it->second[i].substr(j+1, k-j-1);
                        try
                        {
                            int curnum = std::stoi(snum);
                            if (curnum > maxnum)
                            {
                                maxnum = curnum;
                                maxnumidx = i;
                            }
                        }
                        catch(const std::exception& ex)
                        {
                        }
                    }
                }
            }
        }
        //Устанавливаем максимальный элемент последним в массиве
        std::string lm = it->second[it->second.size()-1];
        it->second[it->second.size()-1] = it->second[maxnumidx];
        it->second[maxnumidx] = lm;
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
            if (!result.empty())
            {
                result = std::to_string(std::stoi(result) + 1);
            }
        }
    }
    return result;
}
