#include <string>
#include <vector>
#include <unordered_map>
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

#define ADDRESS_LENGTH 25
#define PUBKEY_LENGTH 65

#ifndef UTILS
#define UTILS

#include "include/libplatform/libplatform.h"
#include "include/v8.h"
#include "include/v8-profiler.h"

std::string DumpToHexString(const std::string& dump);
std::string DumpToHexString(const uint8_t* dump, uint32_t dumpsize);
void HexStringToDump(const std::string& hexstr, std::vector<uint8_t>& dump);
EVP_PKEY* ParsePubDER(unsigned char* binary, size_t binarysize);
ECDSA_SIG* ECSignatureFromBuffer(unsigned char* buff, size_t bufsize, EVP_PKEY* key);
bool CheckBufferSignature(EVP_PKEY* publicKey, const unsigned char* buf,
                            size_t bufsize, ECDSA_SIG* signature);
bool EVPKEYToAddress(EVP_PKEY* pubkey,
                        uint8_t* out,
                        size_t outsize);
bool CreateECKeyPairAndAddr(std::string& privkey,
                            std::string& pubkey,
                            std::string& address,
                            uint8_t netbyte = 0,
                            const char* password = NULL);

std::string ReadFile(const std::string& path);
std::string BytecodeToListing(const std::string& bytecode);
void ParseBytecode(const std::string& bytecode, std::unordered_map<std::string, size_t>& instructions);
std::string RemoveColorCharacters(const std::string& text);

class SnapshotEnumerator
{
public:
    SnapshotEnumerator(){};
    void Reload(const char* directory);
    void FindNewestSnapshots();
    std::unordered_map<std::string, std::vector<std::string> > snapshotsnames;
};

std::string GetNextSnapNumber(const std::string& snapfilename);
bool IsDirectoryExist(const char* dir);

void GetProperties(v8::Isolate* isolate,
                const v8::HeapGraphNode* node,
                std::vector<std::vector<std::string>>& symbols);
const v8::HeapGraphNode* GetProperty(v8::Isolate* isolate,
                                            const v8::HeapGraphNode* node,
                                            v8::HeapGraphEdge::Type type,
                                            const char* name);
std::string SignData(const std::string& data, const std::string& hexprivkey);
bool CheckSign(const std::string& data, const std::string& signature, const std::string& pubkey);
std::string HexPubkeyToAddress(const std::string& hexpubkey, uint8_t firstbyte);
std::string JSONToMethodCall(const std::string& json);

#endif
