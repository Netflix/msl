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

#ifndef SRC_TOKENS_MASTERTOKEN_H_
#define SRC_TOKENS_MASTERTOKEN_H_

#include <Date.h>
#include <Macros.h>
#include <crypto/Key.h>
#include <io/MslEncodable.h>
#include <io/MslEncoderFormat.h>
#include <io/MslObject.h>
#include <map>
#include <memory>
#include <string>
#include <vector>
#include <stdint.h>

namespace netflix {
namespace msl {

typedef std::vector<uint8_t> ByteArray;

// forward class decls
namespace io { class mslObject; class MslEncoderFactory; class MslEncoderFormat; }
namespace util { class MslContext; }

namespace tokens {

/**
 * <p>The master token provides proof of remote entity identity. A MSL-specific
 * crypto context is used to encrypt the master token data and generate the
 * master token verification data. The remote entity cannot decrypt the master
 * token data or generate the master token verification data.</p>
 *
 * <p>The master token session keys will be used for MSL message encryption and
 * integrity protection. The use of these session keys implies the MSL message
 * identity as specified in the master token.</p>
 *
 * <p>Master tokens also contain a sequence number identifying the issue number
 * of the token. This is a monotonically increasing number that is incremented
 * by one each time a master token is renewed.</p>
 *
 * <p>When in possession of multiple master tokens, the token with the highest
 * sequence number should be considered the newest token. Since the sequence
 * number space is signed 53-bit numbers, if a sequence number is smaller by
 * more than 45-bits (e.g. the new sequence number is <= 128 and the old
 * sequence number is 2^53), it is considered the newest token.</p>
 *
 * <p>The renewal window indicates the time after which the master token will
 * be renewed if requested by the entity. The expiration is the time after
 * which the master token will be renewed no matter what.</p>
 *
 * <p>Master tokens also contain a serial number against which all other tokens
 * are bound. Changing the serial number when the master token is renewed
 * invalidates all of those tokens.</p>
 *
 * <p>The issuer identity identifies the issuer of this master token, which may
 * be useful to services that accept the master token.</p>
 *
 * <p>While there can be multiple versions of a master token, this class should
 * encapsulate support for all of those versions.</p>
 *
 * <p>Master tokens are represented as
 * {@code
 * mastertoken = {
 *   "#mandatory" : [ "tokendata", "signature" ],
 *   "tokendata" : "base64",
 *   "signature" : "base64"
 * }} where:
 * <ul>
 * <li>{@code tokendata} is the Base64-encoded master token data (mastertokendata)</li>
 * <li>{@code signature} is the Base64-encoded verification data of the master token data</li>
 * </ul></p>
 *
 * <p>The token data is represented as
 * {@code
 * mastertokendata = {
 *   "#mandatory" : [ "renewalwindow", "expiration", "sequencenumber", "serialnumber", "sessiondata" ],
 *   "renewalwindow" : "int64(0,-)",
 *   "expiration" : "int64(0,-)",
 *   "sequencenumber" : "int64(0,2^53^)",
 *   "serialnumber" : "int64(0,2^53^)",
 *   "sessiondata" : "base64"
 * }} where:
 * <ul>
 * <li>{@code renewalwindow} is when the renewal window opens in seconds since the epoch</li>
 * <li>{@code expiration} is the expiration timestamp in seconds since the epoch</li>
 * <li>{@code sequencenumber} is the master token sequence number</li>
 * <li>{@code serialnumber} is the master token serial number</li>
 * <li>{@code sessiondata} is the Base64-encoded encrypted session data (sessiondata)</li>
 * </ul></p>
 *
 * <p>The decrypted session data is represented as
 * {@code
 * sessiondata = {
 *   "#mandatory" : [ "identity", "encryptionkey" ],
 *   "#conditions" : [ "hmackey" or "signaturekey" ],
 *   "issuerdata" : object,
 *   "identity" : "string",
 *   "encryptionkey" : "base64",
 *   "encryptionkeyalgorithm" : "string",
 *   "hmackey" : "base64",
 *   "signaturekey" : "base64",
 *   "signaturekeyalgorithm" : "string",
 * }}
 * where:
 * <ul>
 * <li>{@code issuerdata} is the master token issuer data</li>
 * <li>{@code identity} is the identifier of the remote entity</li>
 * <li>{@code encryptionkey} is the Base64-encoded encryption session key</li>
 * <li>{@code encryptionkeyalgorithm} is the JCA encryption algorithm name (default: AES/CBC/PKCS5Padding)</li>
 * <li>{@code hmackey} is the Base64-encoded HMAC session key</li>
 * <li>{@code signaturekey} is the Base64-encoded signature session key</li>
 * <li>{@code signaturekeyalgorithm} is the JCA signature algorithm name (default: HmacSHA256)</li>
 * </ul></p>
 */
class MasterToken: public io::MslEncodable
{
public:
    virtual ~MasterToken() {}

    /**
     * Create a new master token with the specified expiration, identity,
     * serial number, and encryption and signature keys.
     *
     * @param ctx MSL context.
     * @param renewalWindow the renewal window.
     * @param expiration the expiration.
     * @param sequenceNumber the master token sequence number.
     * @param serialNumber the master token serial number.
     * @param issuerData the issuer data. May be null.
     * @param identity the singular identity this master token represents.
     * @param encryptionKey the session encryption key.
     * @param signatureKey the session signature key.
     * @throws MslEncodingException if there is an error encoding the data.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the token data or the crypto algorithms are not recognized.
     */
    MasterToken(std::shared_ptr<util::MslContext> ctx, std::shared_ptr<Date> renewalWindow,
            std::shared_ptr<Date> expiration, int64_t sequenceNumber, int64_t serialNumber,
            std::shared_ptr<io::MslObject> issuerData, const std::string& identity,
            const crypto::SecretKey& encryptionKey,
            const crypto::SecretKey& signatureKey);

    /**
     * Create a new master token from the provided MSL object.
     *
     * @param ctx MSL context.
     * @param masterTokenMo master token MSL object.
     * @throws MslEncodingException if there is an error parsing the object,
     *         the token data is missing or invalid, the signature is missing
     *         or invalid, or the session data is missing or invalid.
     * @throws MslCryptoException if there is an error verifying the token data
     *         or extracting the session keys.
     * @throws MslException if the expiration timestamp occurs before the
     *         renewal window, or the sequence number is out of range, or the
     *         serial number is out of range.
     */
    MasterToken(std::shared_ptr<util::MslContext> ctx, std::shared_ptr<io::MslObject> masterTokenMo);

    /**
     * @return true if the decrypted content is available. (Implies verified.)
     */
    bool isDecrypted() const { return (sessiondata_) ? true : false; }

    /**
     * @return true if the token has been verified.
     */
    bool isVerified() const { return verified_; }

    /**
     * @return the start of the renewal window.
     */
    std::shared_ptr<Date> getRenewalWindow() const;

    /**
     * <p>Returns true if the master token renewal window has been entered.</p>
     *
     * <ul>
     * <li>If a time is provided the renewal window value will be compared
     * against the provided time.</li>
     * <li>If the master token was issued by the local entity the renewal
     * window value will be compared against the local entity time. We assume
     * its clock at the time of issuance is in sync with the clock now.</li>
     * <li>Otherwise the master token is considered renewable under the
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
     * <p>Returns true if the master token is expired.</p>
     *
     * <ul>
     * <li>If a time is provided the expiration value will be compared against
     * the provided time.</li>
     * <li>If the master token was issued by the local entity the expiration
     * value will be compared against the local entity time. We assume
     * its clock at the time of issuance is in sync with the clock now.</li>
     * <li>Otherwise the master token is considered not expired under the
     * assumption that the local time is not synchronized with the token-
     * issuing entity time.</li>
     * </ul>
     *
     * @param now the time to compare against. May be {@code null}.
     * @return true if expired.
     */
    bool isExpired(std::shared_ptr<Date> now = std::shared_ptr<Date>()) const;

    /**
     * @return the sequence number.
     */
    int64_t getSequenceNumber() const { return sequenceNumber_; }

    /**
     * @return the serial number.
     */
    int64_t getSerialNumber() const { return serialNumber_; }

    /**
     * <p>A master token is considered newer if its sequence number is greater
     * than another master token. If both the sequence numbers are equal, then
     * the master token with the later expiration date is considered newer.</p>
     *
     * <p>Serial numbers are not taken into consideration when comparing which
     * master token is newer because serial numbers will change when new master
     * tokens are created as opposed to renewed. The caller of this function
     * should already be comparing master tokens that can be used
     * interchangeably (i.e. for the same MSL network).</p>
     *
     * @param that the master token to compare with.
     * @return true if this master token is newer than the provided one.
     */
    bool isNewerThan(std::shared_ptr<MasterToken> other) const;

    /**
     * Returns the issuer data.
     *
     * @return the master token issuer data or null if there is none or it is
     *         unknown (session data could not be decrypted).
     */
    std::shared_ptr<io::MslObject> getIssuerData() const { return issuerdata_; }

    /**
     * Returns the identifier of the authenticated peer.
     *
     * @return the Netflix peer identity or null if unknown (session data could
     *         not be decrypted).
     */
    std::string getIdentity() const { return identity_; }

    /**
     * @return the encryption key or null if unknown (session data could not be
     *         decrypted).
     */
    crypto::SecretKey getEncryptionKey() const { return encryptionKey_; }

    /**
     * @return the signature key or null if unknown (session data could not be
     *         decrypted).
     */
    crypto::SecretKey getSignatureKey() const { return signatureKey_; }

    // io::MslEncodable method override
    virtual std::shared_ptr<ByteArray> toMslEncoding(std::shared_ptr<io::MslEncoderFactory> encoder,
            const io::MslEncoderFormat& format) const;

    /* (non-Javadoc)
     * @see java.lang.Object#toString()
     */
    std::string toString() const;

    /**
     * <p>Returns true if the other master token has the same serial number,
     * sequence number, and expiration. The expiration is considered in the
     * event the issuer renews a master token but is unable or unwilling to
     * increment the sequence number.</p>
     *
     * @param other the master token with which to compare.
     * @return true if the other master token has the same serial number,
     *         sequence number, and expiration.
     * @see #uniqueKey()
     */
    bool equals(std::shared_ptr<const MasterToken> other) const;

    /**
     * @return a unique key suitable for identifying this master token.
     */
    std::string uniqueKey() const;

private:
    /** MSL context. */
    std::shared_ptr<util::MslContext> ctx_;

    /** Master token renewal window in seconds since the epoch. */
    int64_t renewalWindow_;
    /** Master token expiration in seconds since the epoch. */
    int64_t expiration_;
    /** Sequence number. */
    int64_t sequenceNumber_;
    /** Serial number. */
    int64_t serialNumber_;

    /** Issuer data. */
    std::shared_ptr<io::MslObject> issuerdata_;
    /** Entity identity. */
    std::string identity_;
    /** Encryption key. */
    crypto::SecretKey encryptionKey_;
    /** Signature key. */
    crypto::SecretKey signatureKey_;

    /** Session data. */
    std::shared_ptr<io::MslObject> sessiondata_;

    /** Token data bytes. */
    std::shared_ptr<ByteArray> tokendataBytes_;
    /** Signature bytes. */
    std::shared_ptr<ByteArray> signatureBytes_;

    /** Token is verified. */
    bool verified_;

    /** Cached encodings. */
    mutable std::map<io::MslEncoderFormat, std::shared_ptr<ByteArray>> encodings_;

    friend bool operator==(const MasterToken& a, const MasterToken& b);
};

/**
  * @param obj the reference object with which to compare.
  * @return true if the other object is a master token with the same
  *         serial number, sequence number, and expiration values.
  */
bool operator==(const MasterToken& a, const MasterToken& b);
inline bool operator!=(const MasterToken& a, const MasterToken& b) { return !(a == b); }

}}} // namespace netflix::msl:;tokens

#endif /* SRC_TOKENS_MASTERTOKEN_H_ */
