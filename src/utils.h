#include <string>
#include <vector>
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

std::string DumpToHexString(const std::string& dump);
std::string DumpToHexString(const uint8_t* dump, uint32_t dumpsize);
void HexStringToDump(const std::string& hexstr, std::vector<uint8_t>& dump);
EVP_PKEY* ParseDER(unsigned char* binary, size_t binarysize);
ECDSA_SIG* ECSignatureFromBuffer(unsigned char* buff, size_t bufsize, EVP_PKEY* key);
bool CheckBufferSignature(EVP_PKEY* publicKey, const unsigned char* buf,
                            size_t bufsize, ECDSA_SIG* signature);
bool EVPKEYToAddress(EVP_PKEY* pubkey,
                        uint8_t* out,
                        size_t outsize);
std::string ReadFile(const std::string& path);

#endif
