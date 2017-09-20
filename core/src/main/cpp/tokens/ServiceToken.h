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

#ifndef SRC_TOKENS_SERVICETOKEN_H_
#define SRC_TOKENS_SERVICETOKEN_H_

#include <MslConstants.h>
#include <io/MslEncodable.h>
#include <io/MslEncoderFormat.h>
#include <stdint.h>
#include <map>
#include <memory>
#include <string>
#include <vector>

typedef std::vector<uint8_t> ByteArray;

namespace netflix {
namespace msl {
namespace crypto { class ICryptoContext; }
namespace io { class MslEncoderFactory; class MslObject; }
namespace util { class MslContext; }

namespace tokens {

class MasterToken;
class UserIdToken;

/**
 * <p>Service tokens are service-defined tokens carried as part of any MSL
 * message. These tokens should be used to carry service state.</p>
 *
 * <p>Service tokens are optionally bound to a specific master token and user
 * ID token by their serial numbers.</p>
 *
 * <p>Service tokens are either verified or encrypted. Verified tokens carry
 * their data in the clear but are accompanied by a signature allowing the
 * issuer to ensure the data has not been tampered with. Encrypted tokens
 * encrypt their data as well as contain a signature.</p>
 *
 * <p>Service tokens should use application- or service-specific crypto
 * contexts and not the crypto context associated with the entity credentials
 * or master token.</p>
 *
 * <p>Service tokens are represented as
 * {@code
 * servicetoken = {
 *   "#mandatory" : [ "tokendata", "signature" ],
 *   "tokendata" : "binary",
 *   "signature" : "binary"
 * }} where:
 * <ul>
 * <li>{@code tokendata} is the service token data (servicetokendata)</li>
 * <li>{@code signature} is the verification data of the service token data</li>
 * </ul></p>
 *
 * <p>The token data is represented as
 * {@code
 * servicetokendata = {
 *   "#mandatory" : [ "name", "mtserialnumber", "uitserialnumber", "encrypted", "servicedata" ],
 *   "name" : "string",
 *   "mtserialnumber" : "int64(0,2^53^)",
 *   "uitserialnumber" : "int64(0,2^53^)",
 *   "encrypted" : "boolean",
 *   "compressionalgo" : "enum(GZIP|LZW)",
 *   "servicedata" : "binary"
 * }} where:
 * <ul>
 * <li>{@code name} is the token name</li>
 * <li>{@code mtserialnumber} is the master token serial number or -1 if unbound</li>
 * <li>{@code utserialnumber} is the user ID token serial number or -1 if unbound</li>
 * <li>{@code encrypted} indicates if the service data is encrypted or not</li>
 * <li>{@code compressionalgo} indicates the algorithm used to compress the data</li>
 * <li>{@code servicedata} is the optionally encrypted service data</li>
 * </ul></p>
 *
 * <p>Service token names should follow a reverse fully-qualified domain
 * hierarchy. e.g. {@literal com.netflix.service.tokenname}.</p>
 */
class ServiceToken: public io::MslEncodable
{
public:
    virtual ~ServiceToken() {}

    /**
     * <p>Construct a new service token with the specified name and data. If a
     * master token is provided, the service token is bound to the master
     * token's serial number. If a user ID token is provided, the service token
     * is bound to the user ID token's serial number.</p>
     *
     * <p>For encrypted tokens, the token data is encrypted using the provided
     * crypto context. For verified tokens, the token data is signed using the
     * provided crypto context.</p>
     *
     * @param ctx the MSL context.
     * @param name the service token name--must be unique.
     * @param data the service token data (unencrypted).
     * @param masterToken the master token. May be null.
     * @param userIdToken the user ID token. May be null.
     * @param encrypted true if the token should be encrypted.
     * @param compressionAlgo the compression algorithm. May be {@code null}
     *        for no compression.
     * @param cryptoContext the crypto context.
     * @throws MslException if there is an error compressing the data.
     */
    ServiceToken(std::shared_ptr<util::MslContext> ctx, const std::string& name, std::shared_ptr<ByteArray> data,
            std::shared_ptr<MasterToken> masterToken, std::shared_ptr<UserIdToken> userIdToken,
            bool encrypted, const MslConstants::CompressionAlgorithm& compressionAlgo,
            std::shared_ptr<crypto::ICryptoContext> cryptoContext);

    /**
     * <p>Construct a new service token from the provided MSL object and
     * attempt to decrypt and verify the signature of the service token using
     * the appropriate crypto context. If the data cannot be decrypted or the
     * signature cannot be verified, the token will still be created.</p>
     *
     * <p>If the service token name exists as a key in the map of crypto
     * contexts, the mapped crypto context will be used. Otherwise the default
     * crypto context mapped from the empty string key will be used.</p>
     *
     * <p>If a matching crypto context is found, the token data will be
     * decrypted and its signature verified.</p>
     *
     * <p>If the service token is bound to a master token or user ID token it
     * will be verified against the provided master token or user ID tokens
     * which must not be null.</p>
     *
     * @param ctx the MSL context.
     * @param serviceTokenMo the MSL object.
     * @param masterToken the master token. May be null.
     * @param userIdToken the user ID token. May be null.
     * @param cryptoContexts a map of service token names onto crypto contexts.
     * @throws MslEncodingException if there is a problem parsing the data.
     * @throws MslCryptoException if there is an error decrypting or verifying
     *         the token data.
     * @throws MslException if the service token is bound to a master token or
     *         user ID token and the provided tokens are null or the serial
     *         numbers do not match, or if bound to a user ID token but not to
     *         a master token, or if the service data is missing, or if the
     *         compression algorithm is not known or there is an error
     *         uncompressing the data.
     */
    ServiceToken(std::shared_ptr<util::MslContext> ctx, std::shared_ptr<io::MslObject> serviceTokenMo,
            std::shared_ptr<tokens::MasterToken> masterToken, std::shared_ptr<tokens::UserIdToken> userIdToken,
            const std::map<std::string, std::shared_ptr<crypto::ICryptoContext>>& cryptoContexts);

    /**
    * <p>Construct a new service token from the provided MSL object.</p>
    *
    * <p>If a crypto context is provided, the token data will be decrypted and
    * its signature verified. If the data cannot be decrypted or the signature
    * cannot be verified, the token will still be created.</p>
    *
    * <p>If the service token is bound to a master token or user ID token it
    * will be verified against the provided master token or user ID tokens
    * which must not be null.</p>
    *
    * @param ctx the MSL context.
    * @param serviceTokenMo the MSL object.
    * @param masterToken the master token. May be null.
    * @param userIdToken the user ID token. May be null.
    * @param cryptoContext the crypto context. May be null.
    * @throws MslCryptoException if there is a problem decrypting or verifying
    *         the token data.
    * @throws MslEncodingException if there is a problem parsing the data, the
    *         token data is missing or invalid, or the signature is invalid.
    * @throws MslException if the service token is bound to a master token or
    *         user ID token and the provided tokens are null or the serial
    *         numbers do not match, or if bound to a user ID token but not to
    *         a master token, or if the service data is missing, or if the
    *         service token master token serial number is out of range, or if
    *         the service token user ID token serial number is out of range,
    *         or if the compression algorithm is not known or there is an
    *         error uncompressing the data.
    */
   ServiceToken(std::shared_ptr<util::MslContext> ctx, std::shared_ptr<io::MslObject> serviceTokenMo,
           std::shared_ptr<tokens::MasterToken> masterToken, std::shared_ptr<tokens::UserIdToken> userIdToken,
           std::shared_ptr<crypto::ICryptoContext> cryptoContext);

   /**
    * @return true if the content is encrypted.
    */
   bool isEncrypted() const { return encrypted_; }

   /**
    * @return true if the decrypted content is available. (Implies verified.)
    */
   bool isDecrypted() const { return (servicedata_) ? true : false; }

   /**
    * @return true if the token has been verified.
    */
   bool isVerified() const { return verified_; }

   /**
    * @return the application token name.
    */
   std::string getName() const { return name_; }

   /**
    * @return true if this token has been marked for deletion.
    * @see #getData()
    */
   bool isDeleted() const {
       return servicedata_ && servicedata_->empty();
   }

   /**
    * @return the compression algorithm. May be {@code null} if not
    *         compressed.
    */
   MslConstants::CompressionAlgorithm getCompressionAlgo() const { return compressionAlgo_; }

   /**
    * Returns the service data if the token data was not encrypted or we were
    * able to decrypt it.
    *
    * Zero-length data indicates this token should be deleted.
    *
    * @return the service data or null if we don't have it.
    * @see #isDeleted()
    */
   std::shared_ptr<ByteArray> getData() const { return servicedata_; }

   /**
    * Returns the serial number of the master token this service token is
    * bound to.
    *
    * @return the master token serial number or -1 if unbound.
    */
   int64_t getMasterTokenSerialNumber() const { return mtSerialNumber_; }

   /**
    * @return true if this token is bound to a master token.
    */
   bool isMasterTokenBound() const { return mtSerialNumber_ != -1; }

   /**
    * @param masterToken master token. May be null.
    * @return true if this token is bound to the provided master token.
    */
   bool isBoundTo(std::shared_ptr<tokens::MasterToken> masterToken) const;

   /**
    * Returns the serial number of the user ID token this service token is
    * bound to.
    *
    * @return the user ID token serial number or -1 if unbound.
    */
   int64_t getUserIdTokenSerialNumber() const { return uitSerialNumber_; }

   /**
    * Returns true if this token is bound to a user ID token. This implies the
    * token is bound to a master token as well.
    *
    * @return true if this token is bound to a user ID token.
    */
   bool isUserIdTokenBound() const { return uitSerialNumber_ != -1; }

   /**
    * @param userIdToken user ID token. May be null.
    * @return true if this token is bound to the provided user ID token.
    */
   bool isBoundTo(std::shared_ptr<tokens::UserIdToken> userIdToken) const;

   /**
    * @return true if this token is not bound to a master token or user ID
    *         token.
    */
   bool isUnbound() const { return mtSerialNumber_ == -1 && uitSerialNumber_ == -1; }

   /* (non-Javadoc)
   * @see com.netflix.msl.io.MslEncodable#toMslEncoding(com.netflix.msl.io.MslEncoderFactory, com.netflix.msl.io.MslEncoderFormat)
   */
   std::shared_ptr<ByteArray> toMslEncoding(std::shared_ptr<io::MslEncoderFactory> encoder, const io::MslEncoderFormat& format) const;

   /* (non-Javadoc)
    * @see java.lang.Object#toString()
    */
   std::string toString() const;

   /**
    * <p>Returns true if the other service token has the same name and bound
    * to the same tokens.</p>
    *
    * <p>This function is designed for use with sets and maps to guarantee
    * uniqueness of individual service tokens.</p>
    *
    * @param obj the service token with which to compare.
    * @return true if the other service token has the same name and bound to
    *         the same tokens.
    * @see #uniqueKey(java.lang.Object)
    */
   bool equals(std::shared_ptr<const ServiceToken> obj) const;

   /**
    * @return a unique key suitable for identifying this service token.
    */
   std::string uniqueKey() const;

private:
   void init(std::shared_ptr<util::MslContext> ctx, std::shared_ptr<io::MslObject> serviceTokenMo,
           std::shared_ptr<tokens::MasterToken> masterToken, std::shared_ptr<tokens::UserIdToken> userIdToken,
           std::shared_ptr<crypto::ICryptoContext> cryptoContext);

private:
    /** MSL context. */
    std::shared_ptr<util::MslContext> ctx_;
    /** Service token crypto context. */
    std::shared_ptr<crypto::ICryptoContext> cryptoContext_;

    /** The service token name. */
    std::string name_;
    /** The service token master token serial number. */
    int64_t mtSerialNumber_;
    /** The service token user ID token serial number. */
    int64_t uitSerialNumber_;
    /** Service token data is encrypted. */
    bool encrypted_;
    /** Compression algorithm. */
    MslConstants::CompressionAlgorithm compressionAlgo_;
    /** The service token data. */
    std::shared_ptr<ByteArray> servicedata_;
    /** The compressed service token data. */
    std::shared_ptr<ByteArray> compressedServicedata_;

    /** Token data bytes. */
    std::shared_ptr<ByteArray> tokendataBytes_;
    /** Signature bytes. */
    std::shared_ptr<ByteArray> signatureBytes_;

    /** Token is verified. */
    bool verified_;

    /** Cached encodings. */
    mutable std::map<io::MslEncoderFormat, std::shared_ptr<ByteArray>> encodings_;

    // FIXME needs operator< for set
};

/**
 * @param a one instance to compare.
 * @param b the instance with which to compare.
 * @return true if both objects have the same name and are bound to the same tokens.
 */
bool operator==(const ServiceToken& a, const ServiceToken& b);
inline bool operator!=(const ServiceToken& a, const ServiceToken& b) { return !(a == b); }

}}} // namespace netflix::msl::tokens

#endif /* SRC_TOKENS_SERVICETOKEN_H_ */
