/**
 * Copyright (c) 2016 Netflix, Inc.  All rights reserved.
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

#include <crypto/OpenSslLib.h>
#include <MslCryptoException.h>
#include <MslError.h>
#include <MslInternalException.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <algorithm>
#include <cassert>
#include <iostream>
#include <pthread.h>
#include <util/ScopedDisposer.h>
#include <memory>

// TODO: use  *dyn* callbacks??

using namespace std;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
typedef vector<uint8_t> ByteArray;
namespace crypto {

namespace  // anonymous
{

typedef pthread_once_t CRYPTO_once_t;
#define CRYPTO_ONCE_INIT PTHREAD_ONCE_INIT
CRYPTO_once_t once = CRYPTO_ONCE_INIT;

/* CRYPTO_once calls |init| exactly once per process. This is thread-safe: if
 * concurrent threads call |CRYPTO_once| with the same |CRYPTO_once_t| argument
 * then they will block until |init| completes, but |init| will have only been
 * called once.
 *
 * The |once| argument must be a |CRYPTO_once_t| that has been initialized with
 * the value |CRYPTO_ONCE_INIT|. */
void CRYPTO_once(CRYPTO_once_t *once, void (*init)(void)) {
    if (pthread_once(once, init) != 0) {
        abort();
    }
}

void threadid_func(CRYPTO_THREADID *threadId)
{
    CRYPTO_THREADID_set_pointer(threadId, pthread_self());
}

shared_ptr<vector<pthread_mutex_t *> > mutex_array;
//vector<pthread_mutex_t *> mutex_array;

void lock_func(int mode, int n, const char *, int)
{
    assert(!mutex_array->empty());

    if (mode & CRYPTO_LOCK)
    {
        int ret = pthread_mutex_lock(mutex_array->at(n));
        assert(ret == 0);
    }
    else
    {
        int ret = pthread_mutex_unlock(mutex_array->at(n));
        assert(ret == 0);
    }
}

// Implements the callback expected by ERR_print_errors_cb().
// used by GetOpenSSLErrorString below.
int openssl_print_error_callback(const char* msg, size_t msglen, void* u) {
  string* result = reinterpret_cast<string*>(u);
  result->append(msg, msglen);
  return 1;
}

class OpenSslLib
{
public:
    static void init();
    static void cleanup();
private:
    OpenSslLib() {}
    static OpenSslLib *instance();
    void initThread();
    void cleanupThread();
    void initCrypto();
    void cleanupCrypto();
    void initRand();
    DISALLOW_COPY_AND_ASSIGN(OpenSslLib);
};

// static
OpenSslLib * OpenSslLib::instance()
{
    static OpenSslLib *theInstance = new OpenSslLib();
    return theInstance;
}

// static
void OpenSslLib::init()
{
    OPENSSL_no_config();
    instance()->initThread();
    instance()->initCrypto();
    instance()->initRand();
}

// static
void OpenSslLib::cleanup()
{
    instance()->cleanupThread();
    instance()->cleanupCrypto();
}

void OpenSslLib::initThread()
{
    mutex_array.reset(new vector<pthread_mutex_t *>());
    if (!mutex_array->empty())
        throw MslInternalException("Failed OpenSSL thread init, already initialized");
    for (int i=0; i < CRYPTO_num_locks(); ++i)
    {
        pthread_mutex_t * const mutex = new pthread_mutex_t;
        assert(mutex);
        int ret = pthread_mutex_init(mutex, NULL);
        assert(ret == 0);
        mutex_array->push_back(mutex);
    }
    CRYPTO_THREADID_set_callback(threadid_func);
    CRYPTO_set_locking_callback(lock_func);
}

void OpenSslLib::cleanupThread()
{
    CRYPTO_set_locking_callback(NULL);
    int ret = CRYPTO_THREADID_set_callback(NULL);
    assert(ret == 0);
    for (size_t i=0; i < mutex_array->size(); ++i)
    {
        int ret = pthread_mutex_destroy(mutex_array->at(i));
        assert(ret == 0);
        delete mutex_array->at(i);
    }
    mutex_array->clear();
}

void OpenSslLib::initCrypto()
{
#ifndef NDEBUG
    // load error strings for libcrypto
    ERR_load_crypto_strings();
#endif
    OpenSSL_add_all_algorithms(); // FIXME: Add only the stuff we will be using
//    EVP_add_cipher(EVP_aes_128_cbc());
    // EVP_add_digest(EVP_sha1());
    // EVP_add_digest(EVP_sha256());
    // EVP_add_digest(EVP_sha384());
}

void OpenSslLib::cleanupCrypto()
{
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    // ERR_remove_thread_state();
    ERR_free_strings();
}

void OpenSslLib::initRand()
{
    RAND_poll();
}

shared_ptr<ByteArray> evpToSpki(EVP_PKEY * pkey)
{
    if (!pkey)
        throw MslCryptoException(MslError::KEY_EXPORT_ERROR, "RSA EVP_PKEY is null.");
    int outLen = i2d_PUBKEY(pkey, NULL);
    if (outLen <= 0)
        throw MslCryptoException(MslError::KEY_EXPORT_ERROR, "i2d_PUBKEY() returned bad length.");
    shared_ptr<ByteArray> spki = make_shared<ByteArray>(outLen);
    unsigned char * buf = &(*spki)[0];
    int ret = i2d_PUBKEY(pkey, &buf);
    if (!ret)
        throw MslCryptoException(MslError::KEY_EXPORT_ERROR, "i2d_PUBKEY() failed.");
    return spki;
}

shared_ptr<ByteArray> evpToPkcs8(EVP_PKEY * pkey)
{
    if (!pkey)
        throw MslCryptoException(MslError::KEY_EXPORT_ERROR, "RSA EVP_PKEY is null.");
    ScopedDisposer<PKCS8_PRIV_KEY_INFO, void, PKCS8_PRIV_KEY_INFO_free> p8inf(EVP_PKEY2PKCS8(pkey));
    if (!p8inf.get())
        throw MslCryptoException(MslError::KEY_EXPORT_ERROR, "EVP_PKEY2PKCS8() failed.");
    int outLen = i2d_PKCS8_PRIV_KEY_INFO(p8inf.get(), NULL);
    if (outLen <= 0)
        throw MslCryptoException(MslError::KEY_EXPORT_ERROR, "i2d_PKCS8_PRIV_KEY_INFO() returned bad length.");
    shared_ptr<ByteArray> pkcs8 = make_shared<ByteArray>(outLen);
    unsigned char * buf = &(*pkcs8)[0];
    int ret = i2d_PKCS8_PRIV_KEY_INFO(p8inf.get(), &buf);
    if (!ret)
        throw MslCryptoException(MslError::KEY_EXPORT_ERROR, "i2d_PKCS8_PRIV_KEY_INFO() failed.");
    return pkcs8;
}

shared_ptr<ByteArray> bignumToByteArray(const BIGNUM * const bn)
{
    const int sizeBytes = BN_num_bytes(bn);
    shared_ptr<ByteArray> result = make_shared<ByteArray>(sizeBytes, 0);
    unsigned char * buf = &(*result)[0];
    int nCopied = BN_bn2bin(bn, buf);
    if (nCopied != sizeBytes)
        throw MslCryptoException(MslError::KEY_EXPORT_ERROR, "BIGNUM copy out failed.");
    return result;
}

} // namespace anonymous

void ensureOpenSslInit()
{
    CRYPTO_once(&once, OpenSslLib::init);
}

void clearOpenSslErrStack()
{
#ifndef NDEBUG
    const long unsigned int error_num = ERR_peek_error();
    if (error_num == 0)
        return;
    // Uncomment the following line to get internal error strings on stderr.
    cerr << getOpenSSLErrorString() << endl;
#endif
    ERR_clear_error();
}

void shutdownOpenSsl()
{
    OpenSslLib::cleanup();
}

OpenSslErrStackTracer::~OpenSslErrStackTracer()
{
    clearOpenSslErrStack();
}

// Retrieves the OpenSSL error as a string
string getOpenSSLErrorString(void) {
  string result;
  ERR_print_errors_cb(openssl_print_error_callback, &result);
  return result;
}

// static
shared_ptr<RsaEvpKey> RsaEvpKey::fromSpki(const shared_ptr<ByteArray>& spki)
{
    OpenSslErrStackTracer err_tracer;

    // Create an EVP_PKEY from the input SPKI-encoded key, via an RSA key
    const unsigned char * buf = &(*spki)[0];
    ScopedDisposer<RSA, void, RSA_free> rsa(d2i_RSA_PUBKEY(NULL, &buf, spki->size()));
    if (rsa.isEmpty())
        throw MslCryptoException(MslError::KEY_IMPORT_ERROR, "RSA SPKI parsing failed.");
    ScopedDisposer<EVP_PKEY, void, EVP_PKEY_free> pkey(EVP_PKEY_new());
    if (EVP_PKEY_set1_RSA(pkey.get(), rsa.get()) != 1)
        throw MslCryptoException(MslError::KEY_IMPORT_ERROR, "Unable to set public RSA EVP_PKEY.");

    return make_shared<RsaEvpKey>(pkey.release(), false);
}

// static
shared_ptr<RsaEvpKey> RsaEvpKey::fromPkcs8(const shared_ptr<ByteArray>& pkcs8)
{
    // OpenSSL does not make it easy to import a private key that is in PKCS#8
    // format.

    OpenSslErrStackTracer err_tracer;

    // Make a mem BIO pointing to the incoming PKCS#8 data
    char* const data = reinterpret_cast<char*>(const_cast<uint8_t*>(&(*pkcs8)[0]));
    ScopedDisposer<BIO, void, BIO_free_all> bio(BIO_new_mem_buf(data, (int)pkcs8->size()));
    if (bio.isEmpty())
        throw MslCryptoException(MslError::KEY_IMPORT_ERROR, "RSA PKCS#8 BIO failed.");

    // get a PKCS8_PRIV_KEY_INFO struct from the BIO
    ScopedDisposer<PKCS8_PRIV_KEY_INFO, void, PKCS8_PRIV_KEY_INFO_free> p8inf(
        d2i_PKCS8_PRIV_KEY_INFO_bio(bio.get(), NULL));
    if (p8inf.isEmpty())
        throw MslCryptoException(MslError::KEY_IMPORT_ERROR, "RSA PKCS#8 parsing failed.");

    // create a EVP_PKEY from the PKCS8_PRIV_KEY_INFO
    ScopedDisposer<EVP_PKEY, void, EVP_PKEY_free> pkey(EVP_PKCS82PKEY(p8inf.get()));
    if (pkey.isEmpty())
        throw MslCryptoException(MslError::KEY_IMPORT_ERROR, "Unable to set public RSA EVP_PKEY.");

    return make_shared<RsaEvpKey>(pkey.release(), true);
}

// static
shared_ptr<RsaEvpKey> RsaEvpKey::fromRaw(const shared_ptr<ByteArray>& pubMod,
        const shared_ptr<ByteArray>& pubExp, const shared_ptr<ByteArray>& privExp)
{
    // Sanity check sizes so the C-Style cast to int in the bignum conversion
    // below is safe.
    if (pubMod->size() > numeric_limits<int>::max() ||
        pubExp->size() > numeric_limits<int>::max() ||
        (privExp && privExp->size() > numeric_limits<int>::max()))
    {
        throw MslCryptoException(MslError::KEY_IMPORT_ERROR, "RSA key parameter invalid");
    }

    // Make OpenSSL bignums from input parameters
    ScopedDisposer<BIGNUM, void, BN_free> pubModBn(BN_bin2bn(&(*pubMod)[0], (int)pubMod->size(), NULL));
    if (!pubModBn.get())
        throw MslCryptoException(MslError::KEY_IMPORT_ERROR, "RSA key parameter invalid");
    ScopedDisposer<BIGNUM, void, BN_free> pubExpBn(BN_bin2bn(&(*pubExp)[0], (int)pubExp->size(), NULL));
    if (!pubExpBn.get())
        throw MslCryptoException(MslError::KEY_IMPORT_ERROR, "RSA key parameter invalid");
    ScopedDisposer<BIGNUM, void, BN_free> privExpBn;
    bool isPrivate = false;
    if (privExp) {
        privExpBn.reset(BN_bin2bn(&(*privExp)[0], (int)privExp->size(), NULL));
        if (!privExpBn.get())
            throw MslCryptoException(MslError::KEY_IMPORT_ERROR, "RSA key parameter invalid");
        isPrivate = true;
    }

    // Compose an OpenSSL RSA key from the bignums. The RSA struct takes
    // ownership of the bignums, so we need to BN_dup them.
    ScopedDisposer<RSA, void, RSA_free> rsa(RSA_new());
    rsa.get()->n = BN_dup(pubModBn.get());
    rsa.get()->e = BN_dup(pubExpBn.get());
    rsa.get()->d = (privExpBn.get()) ? BN_dup(privExpBn.get()) : NULL;
    rsa.get()->p = NULL;
    rsa.get()->q = NULL;

    // Convert the RSA key to an EVP_PKEY
    ScopedDisposer<EVP_PKEY, void, EVP_PKEY_free> pkey(EVP_PKEY_new());
    if (EVP_PKEY_set1_RSA(pkey.get(), rsa.get()) != 1)
        throw MslCryptoException(MslError::KEY_IMPORT_ERROR, "Unable to convert RSA key to EVP_PKEY.");

    return make_shared<RsaEvpKey>(pkey.release(), isPrivate);
}

shared_ptr<ByteArray> RsaEvpKey::toSpki() const
{
    return evpToSpki(getEvpPkey());
}

shared_ptr<ByteArray> RsaEvpKey::toPkcs8() const
{
    if (!isPrivate)
        throw MslCryptoException(MslError::KEY_EXPORT_ERROR, "PKCS8 encoding of public key is not possible.");
    return evpToPkcs8(getEvpPkey());
}

void RsaEvpKey::toRaw(shared_ptr<ByteArray>& pubMod, shared_ptr<ByteArray>& pubExp,
        shared_ptr<ByteArray>& privExp) const
{
    if (!key)
        throw MslCryptoException(MslError::KEY_EXPORT_ERROR, "RSA EVP_PKEY is null.");
    ScopedDisposer<RSA, void, RSA_free> rsa(EVP_PKEY_get1_RSA(key.get()));
    if (!rsa.get())
        throw MslCryptoException(MslError::KEY_EXPORT_ERROR, "Could not convert EVP_PKEY to RSA key.");
    shared_ptr<ByteArray> modulus = bignumToByteArray(rsa.get()->n);
    shared_ptr<ByteArray> publicExponent = bignumToByteArray(rsa.get()->e);
    if (!modulus || !publicExponent)
        throw MslCryptoException(MslError::KEY_EXPORT_ERROR, "Invalid RSA key.");
    pubMod = modulus;
    pubExp = publicExponent;
    if (rsa.get()->d) {
        shared_ptr<ByteArray> privateExponent = bignumToByteArray(rsa.get()->d);
        if (!privateExponent)
            throw MslCryptoException(MslError::KEY_EXPORT_ERROR, "Invalid RSA private key.");
        privExp = privateExponent;
    } else {
        privExp = make_shared<ByteArray>();
    }
}

}}} // namespace netflix::msl::crypto
