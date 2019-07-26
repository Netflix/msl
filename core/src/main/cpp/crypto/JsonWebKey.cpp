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

#include <crypto/JsonWebKey.h>
#include <crypto/OpenSslLib.h>
#include <io/MslArray.h>
#include <io/MslEncoderFactory.h>
#include <io/MslEncoderFormat.h>
#include <io/MslObject.h>
#include <io/MslEncoderUtils.h>
#include <IllegalArgumentException.h>
#include <MslCryptoException.h>
#include <MslEncodingException.h>
#include <MslError.h>
#include <MslInternalException.h>
#include <string>

using namespace std;
using namespace netflix::msl;
using namespace netflix::msl::io;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace crypto {

namespace {

/** JSON key key type. */
const string KEY_TYPE = "kty";
/** JSON key usage. */
const string KEY_USAGE = "use";
/** JSON key key operations. */
const string KEY_KEY_OPS = "key_ops";
/** JSON key algorithm. */
const string KEY_ALGORITHM = "alg";
/** JSON key extractable. */
const string KEY_EXTRACTABLE = "extractable";
/** JSON key key ID. */
const string KEY_KEY_ID = "kid";

// RSA keys.
/** JSON key modulus. */
const string KEY_MODULUS = "n";
/** JSON key public exponent. */
const string KEY_PUBLIC_EXPONENT = "e";
/** JSON key private exponent. */
const string KEY_PRIVATE_EXPONENT = "d";

// Symmetric keys.
/** JSON key key. */
const string KEY_KEY = "k";

} // namespace anonymous

// ---- JsonWebKey::Type

const JsonWebKey::Type JsonWebKey::Type::rsa(JsonWebKey::Type::rsa_, "RSA");
const JsonWebKey::Type JsonWebKey::Type::oct(JsonWebKey::Type::oct_, "OCT");
const JsonWebKey::Type JsonWebKey::Type::invalid(JsonWebKey::Type::invalid_, "INVALID");

// static
const vector<JsonWebKey::Type>& JsonWebKey::Type::getValues()
{
    static vector<Type> gValues;
    if (gValues.empty()) {
        gValues.push_back(rsa);
        gValues.push_back(oct);
        gValues.push_back(invalid);
    }
    return gValues;
}

// ---- JsonWebKey::Usage

const JsonWebKey::Usage JsonWebKey::Usage::sig(JsonWebKey::Usage::sig_, "SIG");
const JsonWebKey::Usage JsonWebKey::Usage::enc(JsonWebKey::Usage::enc_, "ENC");
const JsonWebKey::Usage JsonWebKey::Usage::wrap(JsonWebKey::Usage::wrap_, "ENC");
const JsonWebKey::Usage JsonWebKey::Usage::invalid(JsonWebKey::Usage::invalid_, "INVALID");

// static
const vector<JsonWebKey::Usage>& JsonWebKey::Usage::getValues()
{
    static vector<Usage> gValues;
    if (gValues.empty()) {
        gValues.push_back(sig);
        gValues.push_back(enc);
        gValues.push_back(wrap);
        gValues.push_back(invalid);
    }
    return gValues;
}

// ---- JsonWebKey::KeyOp

const JsonWebKey::KeyOp JsonWebKey::KeyOp::sign(JsonWebKey::KeyOp::sign_, "SIGN");
const JsonWebKey::KeyOp JsonWebKey::KeyOp::verify(JsonWebKey::KeyOp::verify_, "VERIFY");
const JsonWebKey::KeyOp JsonWebKey::KeyOp::encrypt(JsonWebKey::KeyOp::encrypt_, "ENCRYPT");
const JsonWebKey::KeyOp JsonWebKey::KeyOp::decrypt(JsonWebKey::KeyOp::decrypt_, "DECRYPT");
const JsonWebKey::KeyOp JsonWebKey::KeyOp::wrapKey(JsonWebKey::KeyOp::wrapKey_, "WRAPKEY");
const JsonWebKey::KeyOp JsonWebKey::KeyOp::unwrapKey(JsonWebKey::KeyOp::unwrapKey_, "UNWRAPKEY");
const JsonWebKey::KeyOp JsonWebKey::KeyOp::deriveKey(JsonWebKey::KeyOp::deriveKey_, "DERIVEKEY");
const JsonWebKey::KeyOp JsonWebKey::KeyOp::deriveBits(JsonWebKey::KeyOp::deriveBits_, "DERIVEBITS");
const JsonWebKey::KeyOp JsonWebKey::KeyOp::invalid(JsonWebKey::KeyOp::invalid_, "INVALID");

// static
const vector<JsonWebKey::KeyOp>& JsonWebKey::KeyOp::getValues()
{
    static vector<KeyOp> gValues;
    if (gValues.empty()) {
        gValues.push_back(sign);
        gValues.push_back(verify);
        gValues.push_back(encrypt);
        gValues.push_back(decrypt);
        gValues.push_back(wrapKey);
        gValues.push_back(unwrapKey);
        gValues.push_back(deriveKey);
        gValues.push_back(deriveBits);
        gValues.push_back(invalid);
    }
    return gValues;
}

// ---- JsonWebKey::Algorithm

const JsonWebKey::Algorithm JsonWebKey::Algorithm::HS256(JsonWebKey::Algorithm::hs256_, "HS256");
const JsonWebKey::Algorithm JsonWebKey::Algorithm::RSA1_5(JsonWebKey::Algorithm::rsa1_5_, "RSA1_5");
const JsonWebKey::Algorithm JsonWebKey::Algorithm::RSA_OAEP(JsonWebKey::Algorithm::rsa_oaep_, "RSA-OAEP");
const JsonWebKey::Algorithm JsonWebKey::Algorithm::A128KW(JsonWebKey::Algorithm::a128kw_, "A128KW");
const JsonWebKey::Algorithm JsonWebKey::Algorithm::A128CBC(JsonWebKey::Algorithm::a128cbc_, "A128CBC");
const JsonWebKey::Algorithm JsonWebKey::Algorithm::INVALID(JsonWebKey::Algorithm::invalid_, "INVALID");

// static
const vector<JsonWebKey::Algorithm>& JsonWebKey::Algorithm::getValues()
{
    static vector<Algorithm> gValues;
    if (gValues.empty()) {
        gValues.push_back(HS256);
        gValues.push_back(RSA1_5);
        gValues.push_back(RSA_OAEP);
        gValues.push_back(A128KW);
        gValues.push_back(A128CBC);
        gValues.push_back(INVALID);
    }
    return gValues;
}

string JsonWebKey::Algorithm::getJcaAlgorithmName() const
{
    switch (value()) {
        case hs256_:
            return "HmacSHA256";
        case rsa1_5_:
        case rsa_oaep_:
            return "RSA";
        case a128kw_:
        case a128cbc_:
            return "AES";
        default:
            throw MslInternalException("No JCA standard algorithm name defined for " + toString() + ".");
    }
}

// ---- JsonWebKey

JsonWebKey::JsonWebKey(const Usage& usage, const Algorithm& algo, bool extractable,
        const string& id, shared_ptr<PublicKey> publicKey, shared_ptr<PrivateKey> privateKey)
: type(JsonWebKey::Type::rsa)
, usage(usage)
, algo(algo)
, extractable(extractable)
, id(make_shared<string>(id))
, keyPair(make_shared<KeyPair>(publicKey, privateKey))
{
    if (!publicKey && !privateKey)
        throw MslInternalException("At least one of the public key or private key must be provided.");
    if (algo != Algorithm::INVALID) {
        switch (algo) {
            case Algorithm::rsa1_5_:
            case Algorithm::rsa_oaep_:
                break;
            default:
                throw MslInternalException("The algorithm must be an RSA algorithm.");
        }
    }
}

JsonWebKey::JsonWebKey(const Usage& usage, const Algorithm& algo, bool extractable,
        const string& id, shared_ptr<SecretKey> secretKey)
: type(JsonWebKey::Type::oct)
, usage(usage)
, algo(algo)
, extractable(extractable)
, id(make_shared<string>(id))
, key(secretKey->getEncoded())
, secretKey(secretKey)
{
    if (algo != Algorithm::INVALID) {
        switch (algo) {
            case Algorithm::hs256_:
            case Algorithm::a128kw_:
            case Algorithm::a128cbc_:
                break;
            default:
                throw MslInternalException("The algorithm must be a symmetric key algorithm.");
        }
    }
}

JsonWebKey::JsonWebKey(const set<KeyOp>& keyOps, const Algorithm& algo, bool extractable,
    const string& id, shared_ptr<PublicKey> publicKey, shared_ptr<PrivateKey> privateKey)
: type(JsonWebKey::Type::rsa)
, keyOps(keyOps)
, algo(algo)
, extractable(extractable)
, id(make_shared<string>(id))
, keyPair(make_shared<KeyPair>(publicKey, privateKey))
{
    if (!publicKey && !privateKey)
        throw  MslInternalException("At least one of the public key or private key must be provided.");
    if (algo != Algorithm::INVALID) {
        switch (algo) {
            case Algorithm::rsa1_5_:
            case Algorithm::rsa_oaep_:
                break;
            default:
                throw MslInternalException("The algorithm must be an RSA algorithm.");
        }
    }
}

JsonWebKey::JsonWebKey(const set<KeyOp>& keyOps, const Algorithm& algo, bool extractable,
    const string& id, shared_ptr<SecretKey> secretKey)
: type(JsonWebKey::Type::oct)
, keyOps(keyOps)
, algo(algo)
, extractable(extractable)
, id(make_shared<string>(id))
, key(secretKey->getEncoded())
, secretKey(secretKey)
{
    if (algo != Algorithm::INVALID) {
        switch (algo) {
            case Algorithm::hs256_:
            case Algorithm::a128kw_:
            case Algorithm::a128cbc_:
                break;
            default:
                throw MslInternalException("The algorithm must be a symmetric key algorithm.");
        }
    }
}

JsonWebKey::JsonWebKey(shared_ptr<MslObject> jsonMo)
{
    // Parse JSON object.
    string typeName;
    shared_ptr<string> usageName, algoName;
    set<string> keyOpsNames;
    try {
        typeName = jsonMo->getString(KEY_TYPE);
        if (jsonMo->has(KEY_USAGE))
            usageName = make_shared<string>(jsonMo->getString(KEY_USAGE));
        if (jsonMo->has(KEY_KEY_OPS)) {
            shared_ptr<MslArray> ma = jsonMo->getMslArray(KEY_KEY_OPS);
            for (size_t i = 0; i < ma->size(); ++i)
                keyOpsNames.insert(ma->getString((int)i));
        }
        if (jsonMo->has(KEY_ALGORITHM))
            algoName = make_shared<string>(jsonMo->getString(KEY_ALGORITHM));
        extractable = jsonMo->has(KEY_EXTRACTABLE) ? jsonMo->getBoolean(KEY_EXTRACTABLE) : false;
        if (jsonMo->has(KEY_KEY_ID))
            id = make_shared<string>(jsonMo->getString(KEY_KEY_ID));
    } catch (const MslEncoderException& e) {
        throw MslEncodingException(MslError::MSL_PARSE_ERROR, "jwk " + jsonMo->toString(), e);
    }

    // Set values.
    try {
        type = Type::fromString(typeName);
    } catch (const IllegalArgumentException& e) {
        throw MslCryptoException(MslError::UNIDENTIFIED_JWK_TYPE, typeName, e);
    }
    try {
        usage = (usageName) ? Usage::fromString(*usageName) : Usage::invalid;
    } catch (const IllegalArgumentException& e) {
        throw MslCryptoException(MslError::UNIDENTIFIED_JWK_USAGE, *usageName, e);
    }
    for (set<string>::const_iterator it = keyOpsNames.begin(); it != keyOpsNames.end(); ++it) {
        try {
            keyOps.insert(KeyOp::fromString(*it));
        } catch (const IllegalArgumentException& e) {
            throw MslCryptoException(MslError::UNIDENTIFIED_JWK_KEYOP, *it, e);
        }
    }
    try {
        algo = (algoName) ? Algorithm::fromString(*algoName) : Algorithm::INVALID;
    } catch (const IllegalArgumentException& e) {
        throw MslCryptoException(MslError::UNIDENTIFIED_JWK_ALGORITHM, *algoName, e);
    }

    // Reconstruct keys.
    try {
        // Handle symmetric keys.
        if (type == Type::oct) {
            key = MslEncoderUtils::b64urlDecode(make_shared<string>(jsonMo->getString(KEY_KEY)));
            if (!key || key->size() == 0)
                throw MslCryptoException(MslError::INVALID_JWK_KEYDATA, "symmetric key is empty");
            secretKey = (algo != Algorithm::INVALID) ? make_shared<SecretKey>(key, algo.getJcaAlgorithmName()) : shared_ptr<SecretKey>();
        }

        // Handle public/private keys (RSA only).
        else {
            // Grab the modulus.
            shared_ptr<ByteArray> modulus = MslEncoderUtils::b64urlDecode(make_shared<string>(jsonMo->getString(KEY_MODULUS)));
            if (!modulus || modulus->size() == 0)
                throw MslCryptoException(MslError::INVALID_JWK_KEYDATA, "modulus is empty");

            shared_ptr<ByteArray> nullBa;

            // Reconstruct the public key if it exists.
            shared_ptr<PublicKey> publicKey;
            shared_ptr<ByteArray> publicExponent;
            if (jsonMo->has(KEY_PUBLIC_EXPONENT)) {
                publicExponent = MslEncoderUtils::b64urlDecode(make_shared<string>(jsonMo->getString(KEY_PUBLIC_EXPONENT)));
                if (!publicExponent || publicExponent->size() == 0)
                    throw MslCryptoException(MslError::INVALID_JWK_KEYDATA, "public exponent is empty");
                shared_ptr<ByteArray> spki = RsaEvpKey::fromRaw(modulus, publicExponent, nullBa)->toSpki();
                publicKey = make_shared<PublicKey>(spki, "RSA", PublicKey::DEFAULT_FORMAT);
            }

            // Reconstruct the private key if it exists.
            shared_ptr<PrivateKey> privateKey;
            if (jsonMo->has(KEY_PRIVATE_EXPONENT)) {
                shared_ptr<ByteArray> privateExponent = MslEncoderUtils::b64urlDecode(make_shared<string>(jsonMo->getString(KEY_PRIVATE_EXPONENT)));
                if (!privateExponent || privateExponent->size() == 0)
                    throw MslCryptoException(MslError::INVALID_JWK_KEYDATA, "private exponent is empty");
                shared_ptr<ByteArray> pkcs8 = RsaEvpKey::fromRaw(modulus, nullBa, privateExponent)->toPkcs8();
                privateKey = make_shared<PrivateKey>(pkcs8, "RSA", PrivateKey::DEFAULT_FORMAT);
            }

            // Make sure there is at least one key.
            if (!publicKey && !privateKey)
                throw MslEncodingException(MslError::MSL_PARSE_ERROR, "no public or private key");

            keyPair = make_shared<KeyPair>(publicKey, privateKey);
        }
    } catch (const MslEncoderException& e) {
        throw MslEncodingException(MslError::MSL_PARSE_ERROR, e);
    } catch (const IllegalArgumentException& e) {
        throw MslCryptoException(MslError::INVALID_JWK_KEYDATA, "b64 encoding error");
    }
}

shared_ptr<SecretKey> JsonWebKey::getSecretKey(const string& algorithm) const
{
    // Return the stored symmetric key if it already exists.
    if (secretKey)
        return secretKey;

    // Otherwise construct the secret key.
    if (!key)
        return shared_ptr<SecretKey>();
    try {
        return make_shared<SecretKey>(key, algorithm);
    } catch (const IllegalArgumentException& e) {
        throw MslCryptoException(MslError::INVALID_SYMMETRIC_KEY, e);
    }
}

shared_ptr<ByteArray> JsonWebKey::toMslEncoding(shared_ptr<MslEncoderFactory> encoder,
        const MslEncoderFormat&) const
{
    try {
        shared_ptr<MslObject> mo = encoder->createObject();

        // Encode key attributes.
        mo->put(KEY_TYPE, type.name());
        if (usage != Usage::invalid) mo->put(KEY_USAGE, usage.name());
        if (!keyOps.empty()) {
            shared_ptr<MslArray> keyOpsMa = encoder->createArray();
            for (set<KeyOp>::const_iterator it = keyOps.begin(); it != keyOps.end(); ++it)
                keyOpsMa->put(-1, it->name());
            mo->put(KEY_KEY_OPS, keyOpsMa);
        }
        if (algo != Algorithm::INVALID) mo->put(KEY_ALGORITHM, algo.toString());
        mo->put(KEY_EXTRACTABLE, extractable);
        if (id) mo->put(KEY_KEY_ID, *id);

        // Encode symmetric keys.
        if (type == Type::oct) {
            mo->put<string>(KEY_KEY, *MslEncoderUtils::b64urlEncode(key));
        }

        // Encode public/private keys (RSA only).
        else {
            if (!keyPair)
                throw MslInternalException("No key pair to encode.");
            shared_ptr<PublicKey> publicKey = keyPair->publicKey;
            if (publicKey && publicKey->getFormat() != PublicKey::DEFAULT_FORMAT)
                throw MslInternalException("Bad RSA public key format. (" + publicKey->getFormat() + ")");
            shared_ptr<PrivateKey> privateKey = keyPair->privateKey;
            if (privateKey && privateKey->getFormat() != PrivateKey::DEFAULT_FORMAT)
                throw MslInternalException("Bad RSA private key format. (" + privateKey->getFormat() + ")");

            shared_ptr<ByteArray> mod1, mod2, pubExp, privExp, ignore;
            if (publicKey)
                RsaEvpKey::fromSpki(publicKey->getEncoded())->toRaw(mod1, pubExp, ignore);
            if (privateKey)
                RsaEvpKey::fromPkcs8(privateKey->getEncoded())->toRaw(mod2, ignore, privExp);

            if ((!mod1 && !mod2) || (!pubExp && !privExp))
                throw MslInternalException("Inconsistent RSA key content.");
            if ((mod1 && mod2) && (*mod1 != *mod2))
                throw MslInternalException("Inconsistent RSA modulus.");

            // Encode modulus.
            mo->put(KEY_MODULUS, *MslEncoderUtils::b64urlEncode(mod1 ? mod1 : mod2));

            // Encode public exponent.
            if (pubExp)
                mo->put(KEY_PUBLIC_EXPONENT, *MslEncoderUtils::b64urlEncode(pubExp));

            // Encode private exponent.
            if (privExp)
                mo->put(KEY_PRIVATE_EXPONENT, *MslEncoderUtils::b64urlEncode(privExp));
        }

        // Return the result.
        //
        // We will always encode as JSON.
        return encoder->encodeObject(mo, MslEncoderFormat::JSON);
    } catch (const MslEncoderException& e) {
        throw MslInternalException("Error encoding JsonWebKey", e);
    }
}

}}} // namespace netflix::msl::crypto
