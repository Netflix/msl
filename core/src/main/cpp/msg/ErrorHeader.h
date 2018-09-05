/**
 * Copyright (c) 2016-2018 Netflix, Inc.  All rights reserved.
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

#ifndef SRC_MSG_ERRORHEADER_H_
#define SRC_MSG_ERRORHEADER_H_

#include <Date.h>
#include <msg/Header.h>
#include <io/MslEncoderFormat.h>
#include <MslConstants.h>
#include <stdint.h>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace netflix {
namespace msl {
typedef std::vector<uint8_t> ByteArray;
namespace entityauth { class EntityAuthenticationData; }
namespace io { class MslObject; class MslEncoderFactory; class MslEncoderFormat; }
namespace util { class MslContext; }
namespace msg {

/**
 * <p>The error data is represented as
 * {@code
 * errordata = {
 *   "#mandatory" : [ "messageid", "errorcode" ],
 *   "timestamp" : "int64(0,2^53^)",
 *   "messageid" : "int64(0,2^53^)",
 *   "errorcode" : "int32(0,-)",
 *   "internalcode" : "int32(0,-)",
 *   "errormsg" : "string",
 *   "usermsg" : "string",
 * }} where:
 * <ul>
 * <li>{@code timestamp} is the sender time when the header is created in seconds since the UNIX epoch</li>
 * <li>{@code messageid} is the message ID</li>
 * <li>{@code errorcode} is the error code</li>
 * <li>{@code internalcode} is an service-specific error code</li>
 * <li>{@code errormsg} is a developer-consumable error message</li>
 * <li>{@code usermsg} is a user-consumable localized error message</li>
 * </ul></p>
 */
class ErrorHeader : public Header
{
public:
    virtual ~ErrorHeader() {}

    /**
     * <p>Construct a new error header with the provided error data.</p>
     *
     * @param ctx MSL context.
     * @param entityAuthData the entity authentication data.
     * @param messageId the message ID.
     * @param errorCode the error code.
     * @param internalCode the internal code. Negative to indicate no code.
     * @param errorMsg the error message. May be null.
     * @param userMsg the user message. May be null.
     * @throws MslMessageException if no entity authentication data is
     *         provided.
     */
    ErrorHeader(std::shared_ptr<util::MslContext> ctx, std::shared_ptr<entityauth::EntityAuthenticationData> entityAuthData,
            int64_t messageId, const MslConstants::ResponseCode& errorCode,
            int32_t internalCode, const std::string& errorMsg, const std::string& userMsg);

    /**
     * <p>Construct a new error header from the provided MSL object.</p>
     *
     * @param ctx MSL context.
     * @param errordataBytes error data MSL encoding.
     * @param entityAuthData the entity authentication data.
     * @param signature the header signature.
     * @throws MslEncodingException if there is an error parsing the data.
     * @throws MslCryptoException if there is an error decrypting or verifying
     *         the header.
     * @throws MslEntityAuthException if the entity authentication data is not
     *         supported or erroneous.
     * @throws MslMessageException if there is no entity authentication data
     *         (null), the error data is missing or invalid, the message ID is
     *         negative, or the internal code is negative.
     */
    ErrorHeader(std::shared_ptr<util::MslContext> ctx, std::shared_ptr<ByteArray> errordataBytes,
            std::shared_ptr<entityauth::EntityAuthenticationData> entityAuthData,
            std::shared_ptr<ByteArray> signature);

    /**
     * Returns the entity authentication data.
     *
     * @return the entity authentication data.
     */
    std::shared_ptr<entityauth::EntityAuthenticationData> getEntityAuthenticationData() const
    {
        return entityAuthData_;
    }

    /**
     * @return the timestamp. May be null.
     */
    std::shared_ptr<Date> getTimestamp() const;

    /**
     * @return the message ID.
     */
    int64_t getMessageId() const { return messageId_; }

    /**
     * Returns the error code. If the parsed error code is not recognized then
     * this returns {@code ResponseCode#FAIL}.
     *
     * @return the error code.
     */
    MslConstants::ResponseCode getErrorCode() const { return errorCode_; }

    /**
     * @return the internal code or -1 if none provided.
     */
    int32_t getInternalCode() const { return internalCode_; }

    /**
     * @return the error message. May be null.
     */
    std::string getErrorMessage() const { return errorMsg_; }

    /**
     * @return the user message. May be null.
     */
    std::string getUserMessage() const { return userMsg_; }

    /** @inheritDoc */
    virtual std::shared_ptr<ByteArray> toMslEncoding(std::shared_ptr<io::MslEncoderFactory> encoder, const io::MslEncoderFormat& format) const;

    /* (non-Javadoc)
     * @see java.lang.Object#equals(java.lang.Object)
     */
    virtual bool equals(std::shared_ptr<const Header> other) const;

protected:
    /** MSL context. */
    std::shared_ptr<util::MslContext> ctx_;
    /** Entity authentication data. */
    std::shared_ptr<entityauth::EntityAuthenticationData> entityAuthData_;
    /** Error data. */
    std::shared_ptr<io::MslObject> errordata_;
    /** Cached encodings. */
    mutable std::map<io::MslEncoderFormat, std::shared_ptr<ByteArray>> encodings_;

private:
    ErrorHeader(); // not implemented

    /** Timestamp in seconds since the epoch. */
    int64_t timestamp_;
    /** Message ID. */
    int64_t messageId_;
    /** Error code. */
    MslConstants::ResponseCode errorCode_;
    /** Internal code. */
    int32_t internalCode_;   // FIXME: int64_t?
    /** Error message. */
    std::string errorMsg_; // Note: empty means java null
    /** User message. */
    std::string userMsg_; // Note: empty means java null

    friend std::ostream& operator<<(std::ostream& os, const ErrorHeader& header);
};

bool operator==(const ErrorHeader& a, const ErrorHeader& b);
inline bool operator!=(const ErrorHeader& a, const ErrorHeader& b) { return !(a == b); }

std::ostream& operator<<(std::ostream& os, const ErrorHeader& header);
std::ostream& operator<<(std::ostream& os, std::shared_ptr<ErrorHeader> header);

}}} // namespace netflix::msl::msg

#endif /* SRC_MSG_ERRORHEADER_H_ */
