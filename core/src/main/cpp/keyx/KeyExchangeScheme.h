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

#ifndef SRC_KEYX_KEYEXCHANGESCHEME_H_
#define SRC_KEYX_KEYEXCHANGESCHEME_H_
#include <util/StaticMslMutex.h>
#include <map>
#include <string>
#include <vector>

namespace netflix {
namespace msl {
namespace keyx {

class KeyExchangeScheme;
bool operator==(const KeyExchangeScheme& a, const KeyExchangeScheme& b);
inline bool operator!=(const KeyExchangeScheme& a, const KeyExchangeScheme& b) { return !(a == b); }

/**
 * <p>Key exchange schemes.</p>
 *
 * <p>The scheme name is used to uniquely identify key exchange schemes.</p>
 */
class KeyExchangeScheme
{
public:
    typedef std::map<std::string, KeyExchangeScheme> MapType;

    virtual ~KeyExchangeScheme() {}

    /** Asymmetric key wrapped. */
    static KeyExchangeScheme ASYMMETRIC_WRAPPED;
    /** Diffie-Hellman exchange (Netflix SHA-384 key derivation). */
    static KeyExchangeScheme DIFFIE_HELLMAN;
    /** JSON web encryption ladder exchange. */
    static KeyExchangeScheme JWE_LADDER;
    /** JSON web key ladder exchange. */
    static KeyExchangeScheme JWK_LADDER;
    /** Symmetric key wrapped. */
    static KeyExchangeScheme SYMMETRIC_WRAPPED;
    /** Invalid. */
    static KeyExchangeScheme INVALID;

    /**
     * @param name the key exchange scheme name.
     * @return the scheme identified by the specified name or {@code null} if
     *         there is none.
     */
    static KeyExchangeScheme getScheme(const std::string& name);

    /**
     * @return all known key exchange schemes.
     */
    static std::vector<KeyExchangeScheme> values();

    /**
     * @return the scheme identifier.
     */
    std::string name() const { return name_; }

    /* (non-Javadoc)
     * @see java.lang.Object#toString()
     */
    std::string toString() const { return name(); }

    /* (non-Javadoc)
     * @see java.lang.Object#equals(java.lang.Object)
     */
    bool equals(const KeyExchangeScheme& other) const { return *this == other; }

//protected:  // ctor must be public to allow subclass static init
    /**
     * Define a key exchange scheme with the specified name.
     *
     * @param name the key exchange scheme name.
     */
    KeyExchangeScheme(const std::string& name);

private:
    static util::StaticMslMutex& mutex();
    /** Map of names onto schemes. */
    static MapType& schemes();
    /** Scheme name. */
    std::string name_;
};

inline bool operator<(const KeyExchangeScheme& a, const KeyExchangeScheme &b) { return a.name() < b.name(); }

}}} // namespace netflix::msl::keyx

#endif /* SRC_KEYX_KEYEXCHANGESCHEME_H_ */
