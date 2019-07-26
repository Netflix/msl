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

#ifndef SRC_CRYPTO_KEY_H_
#define SRC_CRYPTO_KEY_H_

#include <memory>
#include <string>
#include <vector>

namespace netflix {
namespace msl {
typedef std::vector<uint8_t> ByteArray;
namespace crypto {

class IKey
{
public:
    virtual std::string getAlgorithm() const = 0;
    virtual std::shared_ptr<ByteArray> getEncoded() const = 0;
    virtual std::string getFormat() const = 0;
    virtual bool isNull() const = 0;
    virtual size_t size() const = 0;
protected:
    virtual ~IKey() {}
};

class Key : public IKey
{
public:
    virtual ~Key() {}
    inline virtual std::string getAlgorithm() const {return algorithm_;}
    inline virtual std::shared_ptr<ByteArray> getEncoded() const {return key_;}
    inline virtual std::string getFormat() const {return format_;}
    inline virtual bool isNull() const {return isNull_;}
    inline virtual size_t size() const {return key_->size();}
protected:
    Key(const std::string& format) : isNull_(true), algorithm_("NULL"), format_(format) {}
    Key(std::shared_ptr<ByteArray> key, const std::string& algorithm, const std::string& format);
    Key(const Key& other);
    Key operator=(const Key& rhs);
private:
    bool isNull_;
    std::shared_ptr<ByteArray> key_; // holds the default encoding of the key
    std::string algorithm_;
    std::string format_;
};

class SecretKey : public Key
{
public:
    virtual ~SecretKey() {}
    SecretKey() : Key(DEFAULT_FORMAT) {}
    SecretKey(std::shared_ptr<ByteArray> key, const std::string& algorithm) : Key(key, algorithm, DEFAULT_FORMAT) {}
    SecretKey(const SecretKey& other) : Key(other) {}
    using Key::operator=;
    static const char *DEFAULT_FORMAT;
};

class PrivateKey : public Key
{
public:
    virtual ~PrivateKey() {}
    PrivateKey() : Key(DEFAULT_FORMAT) {}
    PrivateKey(std::shared_ptr<ByteArray> key, const std::string& algorithm) : Key(key, algorithm, DEFAULT_FORMAT) {}
    PrivateKey(std::shared_ptr<ByteArray> key, const std::string& algorithm, const std::string& format) : Key(key, algorithm, format) {}
    PrivateKey(const PrivateKey& other) : Key(other) {}
    using Key::operator=;
    static const char *DEFAULT_FORMAT;
};

class PublicKey : public Key
{
public:
    virtual ~PublicKey() {}
    PublicKey() : Key(DEFAULT_FORMAT) {}
    PublicKey(std::shared_ptr<ByteArray> key, const std::string& algorithm) : Key(key, algorithm, DEFAULT_FORMAT) {}
    PublicKey(std::shared_ptr<ByteArray> key, const std::string& algorithm, const std::string& format) : Key(key, algorithm, format) {}
    PublicKey(const PublicKey& other) : Key(other) {}
    using Key::operator=;
    static const char *DEFAULT_FORMAT;
};

struct KeyPair
{
    KeyPair(std::shared_ptr<PublicKey> pub, std::shared_ptr<PrivateKey> priv) : publicKey(pub), privateKey(priv) {}
    std::shared_ptr<PublicKey> publicKey;
    std::shared_ptr<PrivateKey> privateKey;
};

bool operator==(const IKey& a, const IKey& b);
inline bool operator!=(const IKey& a, const IKey& b) { return !(a == b); }

}}} // namespace netflix::msl::crypto

#endif /* SRC_CRYPTO_KEY_H_ */
