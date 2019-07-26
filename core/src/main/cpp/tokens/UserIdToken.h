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

#ifndef SRC_TOKENS_USERIDTOKEN_H_
#define SRC_TOKENS_USERIDTOKEN_H_

#include <Date.h>
#include <io/MslEncodable.h>
#include <io/MslEncoderFormat.h>
#include <io/MslObject.h>
#include <stdint.h>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace netflix {
namespace msl {
typedef std::vector<uint8_t> ByteArray;
namespace io { class MslEncoderFactory; }
namespace util { class MslContext; }
namespace tokens {

class MasterToken;
class MslUser;

/**
 * <p>A user ID token provides proof of user identity. While there can be
 * multiple versions of a user ID token, this class should encapsulate support
 * for all of those versions.</p>
 *
 * <p>User ID tokens are bound to a specific master token by the master token's
 * serial number.</p>
 *
 * <p>The renewal window indicates the time after which the user ID token will
 * be renewed if requested by the entity. The expiration is the time after
 * which the user ID token will be renewed no matter what.</p>
 *
 * <p>User ID tokens are represented as
 * {@code
 * useridtoken = {
 *   "#mandatory" : [ "tokendata", "signature" ],
 *   "tokendata" : "binary",
 *   "signature" : "binary"
 * }} where:
 * <ul>
 * <li>{@code tokendata} is the user ID token data (usertokendata)</li>
 * <li>{@code signature} is the verification data of the user ID token data</li>
 * </ul>
 *
 * <p>The token data is represented as
 * {@code
 * usertokendata = {
 *   "#mandatory" : [ "renewalwindow", "expiration", "mtserialnumber", "serialnumber", "userdata" ],
 *   "renewalwindow" : "int64(0,-)",
 *   "expiration" : "int64(0,-)",
 *   "mtserialnumber" : "int64(0,2^53^)",
 *   "serialnumber" : "int64(0,2^53^)",
 *   "userdata" : "binary"
 * }} where:
 * <ul>
 * <li>{@code renewalwindow} is when the renewal window opens in seconds since the epoch</li>
 * <li>{@code expiration} is the expiration timestamp in seconds since the epoch</li>
 * <li>{@code mtserialnumber} is the master token serial number</li>
 * <li>{@code serialnumber} is the user ID token serial number</li>
 * <li>{@code userdata} is the encrypted user data (userdata)</li>
 * </ul></p>
 *
 * <p>The decrypted user data is represented as
 * {@code
 * userdata = {
 *   "#mandatory" : [ "identity" ],
 *   "issuerdata" : object,
 *   "identity" : "string"
 * }}
 * where:
 * <ul>
 * <li>{@code issuerdata} is the user ID token issuer data</li>
 * <li>{@code identity} is the encoded user identity data</li>
 * </ul></p>
 */
class UserIdToken: public io::MslEncodable
{
public:
    virtual ~UserIdToken() {}

    /**
     * Create a new user ID token with the specified user.
     *
     * @param ctx MSL context.
     * @param renewalWindow the renewal window.
     * @param expiration the expiration.
     * @param masterToken the master token.
     * @param serialNumber the user ID token serial number.
     * @param issuerData the issuer data. May be null.
     * @param user the MSL user.
     * @throws MslEncodingException if there is an error encoding the data.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the token data.
     */
    UserIdToken(std::shared_ptr<util::MslContext> ctx, std::shared_ptr<Date> renewalWindow,
            std::shared_ptr<Date> expiration, std::shared_ptr<MasterToken> masterToken, int64_t serialNumber,
            std::shared_ptr<io::MslObject> issuerData, std::shared_ptr<MslUser> user);

    /**
     * Create a new user ID token from the provided MSL object. The associated
     * master token must be provided to verify the user ID token.
     *
     * @param ctx MSL context.
     * @param userIdTokenMo user ID token MSL object.
     * @param masterToken the master token.
     * @throws MslEncodingException if there is an error parsing the data, the
     *         token data is missing or invalid, or the signature is invalid.
     * @throws MslCryptoException if there is an error verifying the token
     *         data.
     * @throws MslException if the user ID token master token serial number
     *         does not match the master token serial number, or the expiration
     *         timestamp occurs before the renewal window, or the user data is
     *         missing or invalid, or the user ID token master token serial
     *         number is out of range, or the user ID token serial number is
     *         out of range.
     */
    UserIdToken(std::shared_ptr<util::MslContext> ctx, std::shared_ptr<io::MslObject> userIdTokenMo,
            std::shared_ptr<MasterToken> masterToken);

    /**
     * @return true if the decrypted content is available. (Implies verified.)
     */
    bool isDecrypted() const { return user_.get(); }

    /**
     * @return true if the token has been verified.
     */
    bool isVerified() const { return verified_; }

    /**
     * @return the start of the renewal window.
     */
    std::shared_ptr<Date> getRenewalWindow() const;

    /**
     * <p>Returns true if the user ID token renewal window has been entered.</p>
     *
     * <ul>
     * <li>If a time is provided the renewal window value will be compared
     * against the provided time.</li>
     * <li>If the user ID token was issued by the local entity the renewal
     * window value will be compared against the local entity time. We assume
     * its clock at the time of issuance is in sync with the clock now.</li>
     * <li>Otherwise the user ID token is considered renewable under the
     * assumption that the local time is not synchronized with the master token
     * issuing entity time.</li>
     * </ul>
     *
     * @param now the time to compare against. May be {@code null}.
     * @return true if the renewal window has been entered.
     */
    bool isRenewable(std::shared_ptr<Date> now = std::shared_ptr<Date>()) const;

    /**
     * @return the expiration.
     */
    std::shared_ptr<Date> getExpiration() const;

    /**
     * <p>Returns true if the user ID token is expired.</p>
     *
     * <ul>
     * <li>If a time is provided the expiration value will be compared against
     * the provided time.</li>
     * <li>If the user ID token was issued by the local entity the expiration
     * value will be compared against the local entity time. We assume
     * its clock at the time of issuance is in sync with the clock now.</li>
     * <li>Otherwise the user ID token is considered not expired under the
     * assumption that the local time is not synchronized with the token-
     * issuing entity time.</li>
     * </ul>
     *
     * @param now the time to compare against. May be {@code null}.
     * @return true if expired.
     */
    bool isExpired(std::shared_ptr<Date> now = std::shared_ptr<Date>()) const;

    /**
     * @return the user ID token issuer data or null if there is none or it is
     *         unknown (user data could not be decrypted).
     */
    std::shared_ptr<io::MslObject> getIssuerData() const { return issuerdata_; }

    /**
     * @return the MSL user, or null if unknown (user data could not be
     *         decrypted).
     */
    std::shared_ptr<tokens::MslUser> getUser() const { return user_; }

    /**
     * @return the user ID token serial number.
     */
    int64_t getSerialNumber() const { return serialNumber_; }

    /**
     * Return the serial number of the master token this user ID token is bound
     * to.
     *
     * @return the master token serial number.
     */
    int64_t getMasterTokenSerialNumber() const { return mtSerialNumber_; }

    /**
     * @param masterToken master token. May be null.
     * @return true if this token is bound to the provided master token.
     */
    bool isBoundTo(std::shared_ptr<tokens::MasterToken> masterToken);

    /** @inheritDoc */
    virtual std::shared_ptr<ByteArray> toMslEncoding(std::shared_ptr<io::MslEncoderFactory> encoder, const io::MslEncoderFormat& format) const;

    /* (non-Javadoc)
     */
    std::string toString() const;

    /**
     * <p>Returns true if the other user ID token has the same serial number
     * bound to the same master token.</p>
     *
     * <p>This function is designed for use with sets and maps to guarantee
     * uniqueness of individual user ID tokens.</p>
     *
     * @param other the user ID token with which to compare.
     * @return true if the other user ID token has the same serial number bound
     *         to the same master token.
     * @see #uniqueKey()
     */
    bool equals(std::shared_ptr<const UserIdToken> other) const;

    /**
     * @return a unique key suitable for identifying this user ID token.
     */
    std::string uniqueKey() const;

private:
    /** MSL context. */
    std::shared_ptr<util::MslContext> ctx_;

    /** User ID token renewal window in seconds since the epoch. */
    int64_t renewalWindow_;
    /** User ID token expiration in seconds since the epoch. */
    int64_t expiration_;
    /** Master token serial number. */
    int64_t mtSerialNumber_;
    /** Serial number. */
    int64_t serialNumber_;
    /** User data. */
    std::shared_ptr<io::MslObject> userdata_;

    /** Issuer data. */
    std::shared_ptr<io::MslObject> issuerdata_;
    /** MSL user. */
    std::shared_ptr<MslUser> user_;

    /** Token data bytes. */
    std::shared_ptr<ByteArray> tokendataBytes_;
    /** Signature bytes. */
    std::shared_ptr<ByteArray> signatureBytes_;

    /** Token is verified. */
    bool verified_;

    /** Cached encodings. */
    mutable std::map<io::MslEncoderFormat, std::shared_ptr<ByteArray>> encodings_;
};

bool operator==(const UserIdToken& a, const UserIdToken& b);
inline bool operator!=(const UserIdToken& a, const UserIdToken& b) { return !(a == b); }

}}} // namespace netflix::msl:;tokens

#endif /* SRC_TOKENS_USERIDTOKEN_H_ */
