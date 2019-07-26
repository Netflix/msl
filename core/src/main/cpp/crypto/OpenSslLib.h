/**
 * Copyright (c) 2016-2017 Netflix, Inc.  All rights reserved.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SRC_CRYPTO_OPENSSLLIB_H_
#define SRC_CRYPTO_OPENSSLLIB_H_

#include <Macros.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <util/ScopedDisposer.h>
#include <string>
#include <vector>

namespace netflix {
namespace msl {
typedef std::vector<uint8_t> ByteArray;
namespace crypto {

void ensureOpenSslInit();

void clearOpenSslErrStack();

void shutdownOpenSsl();

// Place an instance of this class on the call stack to ensure OpenSSL is
// initialized, and to automatically clear the OpenSSL error stack on function
// exit.
class OpenSslErrStackTracer
{
public:
    explicit OpenSslErrStackTracer() { ensureOpenSslInit(); }
    ~OpenSslErrStackTracer();
private:
    DISALLOW_COPY_AND_ASSIGN(OpenSslErrStackTracer);
};

std::string getOpenSSLErrorString(void);

void aesCbcEncrypt(const ByteArray& key, const ByteArray& iv, const ByteArray& plaintext, ByteArray& ciphertext);
void aesCbcDecrypt(const ByteArray& key, const ByteArray& iv, const ByteArray& ciphertext, ByteArray& plaintext);

void aesKwWrap(const ByteArray& wrappingKey, const ByteArray& keyToWrap, ByteArray& wrappedKey);
void aesKwUnwrap(const ByteArray& wrappingKey, const ByteArray& wrappedKey, ByteArray& unwrappedKey);

void signHmacSha256(const ByteArray& key, const ByteArray& data, ByteArray& sig);
bool verifyHmacSha256(const ByteArray& key, const ByteArray& data, const ByteArray& sig);

void signAesCmac(const ByteArray& key, const ByteArray& data, ByteArray& sig);
bool verifyAesCmac(const ByteArray& key, const ByteArray& data, const ByteArray& inSig);

void rsaEncrypt(EVP_PKEY* pkey, const ByteArray& plaintext, bool isOaepPadding, ByteArray& ciphertext);
void rsaDecrypt(EVP_PKEY* pkey, const ByteArray& ciphertext, bool isOaepPadding, ByteArray& plaintext);

void rsaSign(EVP_PKEY* pkey, const ByteArray& data, ByteArray& signature);
bool rsaVerify(EVP_PKEY* pkey, const ByteArray& data, const ByteArray& signature);

void dhGenKeyPair(const ByteArray& p, const ByteArray& g, ByteArray& pubKey, ByteArray& privKey);
void dhComputeSharedSecret(const ByteArray& remotePublicKey, const ByteArray& p,
        const ByteArray& localPrivateKey, ByteArray& sharedSecret);

void digest(const std::string& spec, const ByteArray& data, ByteArray& md);

void hmacSha(const std::string& shaAlg, const ByteArray& key, const ByteArray& data, ByteArray& sig);

class RsaEvpKey
{
public:
    static std::shared_ptr<RsaEvpKey> fromSpki(const std::shared_ptr<ByteArray>& spki);
    static std::shared_ptr<RsaEvpKey> fromPkcs8(const std::shared_ptr<ByteArray>& pkcs8);
    static std::shared_ptr<RsaEvpKey> fromRaw(const std::shared_ptr<ByteArray>& pubMod,
            const std::shared_ptr<ByteArray>& pubExp, const std::shared_ptr<ByteArray>& privExp);
    EVP_PKEY * getEvpPkey() const {return key.get();}
    std::shared_ptr<ByteArray> toSpki() const;
    std::shared_ptr<ByteArray> toPkcs8() const;
    void toRaw(std::shared_ptr<ByteArray>& pubMod, std::shared_ptr<ByteArray>& pubExp, std::shared_ptr<ByteArray>& privExp) const;
    RsaEvpKey(EVP_PKEY * key, bool isPrivate) : key(key), isPrivate(isPrivate) {}
private:
    const util::ScopedDisposer<EVP_PKEY, void, EVP_PKEY_free> key;
    const bool isPrivate;
};

}}} // namespace netflix::msl::crypto

#endif /* SRC_CRYPTO_OPENSSLLIB_H_ */
