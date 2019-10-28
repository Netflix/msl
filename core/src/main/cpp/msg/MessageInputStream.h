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
#ifndef SRC_MSG_MESSAGEINPUTSTREAM_H_
#define SRC_MSG_MESSAGEINPUTSTREAM_H_

#include <io/InputStream.h>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>
#include <msg/PayloadChunk.h>

namespace netflix {
namespace msl {
class IOException;
namespace crypto { class ICryptoContext; }
namespace io { class ByteArrayInputStream; class MslObject; class MslTokenizer; }
namespace keyx { class KeyRequestData; }
namespace tokens { class MslUser; }
namespace util { class MslContext; }
namespace msg {
class ErrorHeader; class Header; class MessageHeader;

class MessageInputStream : public io::InputStream
{
public:
	/** Unknown identity. */
	static const std::string UNKNOWN_IDENTITY;

	/** Destructor. */
	virtual ~MessageInputStream() { close(); }

    /**
     * <p>Construct a new message input stream. The header is parsed.</p>
     *
     * <p>If key request data is provided and a matching key response data is
     * found in the message header the key exchange will be performed to
     * process the message payloads.</p>
     *
     * <p>Service tokens will be decrypted and verified with the provided crypto
     * contexts identified by token name. A default crypto context may be
     * provided by using the empty string as the token name; if a token name is
     * not explcitly mapped onto a crypto context, the default crypto context
     * will be used.</p>
     *
     * @param ctx MSL context.
     * @param source MSL input stream.
     * @param keyRequestData key request data to use when processing key
     *        response data.
     * @param cryptoContexts the map of service token names onto crypto
     *        contexts used to decrypt and verify service tokens.
     * @throws IOException if there is a problem reading from the input stream.
     * @throws MslEncodingException if there is an error parsing the message.
     * @throws MslCryptoException if there is an error decrypting or verifying
     *         the header or creating the message payload crypto context.
     * @throws MslEntityAuthException if unable to create the entity
     *         authentication data.
     * @throws MslUserAuthException if unable to create the user authentication
     *         data.
     * @throws MslMessageException if the message master token is expired and
     *         the message is not renewable.
     * @throws MslMasterTokenException if the master token is not trusted and
     *         needs to be or if it has been revoked.
     * @throws MslUserIdTokenException if the user ID token has been revoked.
     * @throws MslKeyExchangeException if there is an error with the key
     *         request data or key response data or the key exchange scheme is
     *         not supported.
     * @throws MslMessageException if the message does not contain an entity
     *         authentication data or a master token, the header data is
     *         missing or invalid, or the message ID is negative, or the
     *         message is not encrypted and contains user authentication data,
     *         or if the message master token is expired and the message is not
     *         renewable.
     * @throws MslException if the message does not contain an entity
     *         authentication data or a master token, or a token is improperly
     *         bound to another token.
     */
    MessageInputStream(std::shared_ptr<util::MslContext> ctx,
    		std::shared_ptr<io::InputStream> source,
			std::set<std::shared_ptr<keyx::KeyRequestData>> keyRequestData,
			std::map<std::string,std::shared_ptr<crypto::ICryptoContext>> cryptoContexts);

    /**
     * Returns true if the message is a handshake message.
     *
     * FIXME
     * This method should be removed by a direct query of the message header
     * once the old behavior of inferred handshake messages based on a single
     * empty payload chunk is no longer supported.
     *
     * @return true if the message is a handshake message.
     * @throws MslCryptoException if there is a problem decrypting or verifying
     *         the payload chunk.
     * @throws MslEncodingException if there is a problem parsing the data.
     * @throws MslMessageException if the payload verification failed.
     * @throws MslInternalException if attempting to access payloads of an
     *         error message.
     * @throws MslException if there is an error uncompressing the data.
     */
    virtual bool isHandshake();

    /**
     * @return the message header. Will be null for error messages.
     */
    virtual std::shared_ptr<msg::MessageHeader> getMessageHeader();

    /**
     * @return the error header. Will be null except for error messages.
     */
    virtual std::shared_ptr<msg::ErrorHeader> getErrorHeader();

    /**
     * Returns the sender's entity identity. The identity will be unknown if
     * the local entity is a trusted network client and the message was sent by
     * a trusted network server using the local entity's master token.
     *
     * @return the sender's entity identity or {@link #UNKNOWN_IDENTITY} if
     *         unknown.
     * @throws MslCryptoException if there is a crypto error accessing the
     *         entity identity;
     */
    virtual std::string getIdentity();

    /**
     * Returns the user associated with the message. The user will be unknown
     * if the local entity is a trusted network client and the message was sent
     * by a trusted network server.
     *
     * @return the user associated with the message or null if unknown.
     */
    virtual std::shared_ptr<tokens::MslUser> getUser();

    /**
     * @return the payload crypto context. Will be null for error messages.
     */
    virtual std::shared_ptr<crypto::ICryptoContext> getPayloadCryptoContext() { return cryptoContext_; }

    /**
     * @return the key exchange crypto context. Will be null if no key response
     *         data was returned in this message and for error messages.
     */
    virtual std::shared_ptr<crypto::ICryptoContext> getKeyExchangeCryptoContext() { return keyxCryptoContext_; }

    /**
     * Returns true if the payload application data is encrypted. This will be
     * true if the entity authentication scheme provides encryption or if
     * session keys were used. Returns false for error messages which do not
     * have any payload chunks.
     *
     * @return true if the payload application data is encrypted. Will be false
     *         for error messages.
     */
    virtual bool encryptsPayloads();

    /**
     * Returns true if the payload application data is integrity protected.
     * This will be true if the entity authentication scheme provides integrity
     * protection or if session keys were used. Returns false for error
     * messages which do not have any payload chunks.
     *
     * @return true if the payload application data is integrity protected.
     *         Will be false for error messages.
     */
    virtual bool protectsPayloadIntegrity();

    /**
     * By default the source input stream is not closed when this message input
     * stream is closed. If it should be closed then this method can be used to
     * dictate the desired behavior.
     *
     * @param close true if the source input stream should be closed, false if
     *        it should not.
     */
    virtual void closeSource(bool close) { closeSource_ = close; }

    /** @inheritDoc */
    virtual void abort();

    /** @inheritDoc */
    virtual bool close(int timeout = -1);

    /** @inheritDoc */
    virtual void mark(size_t readlimit);

    /** @inheritDoc */
    virtual bool markSupported() { return true; }
    /** @inheritDoc */
    virtual int read(ByteArray& out, int timeout = -1) { return read(out, 0, out.size(), timeout); }

    /** @inheritDoc */
    virtual int read(ByteArray& out, size_t offset, size_t len, int timeout = -1);

    /** @inheritDoc */
    virtual void reset();

protected:
    /**
     * Retrieve the next MSL object.
     *
     * @return the next MSL object or null if none remaining.
     * @throws MslEncodingException if there is a problem parsing the data.
     */
    std::shared_ptr<io::MslObject> nextMslObject();

    /**
     * Retrieve the next payload chunk data.
     *
     * @param out the next payload chunk data container.
     * @return true if the next chunk was retreived, false if none remaining.
     * @throws MslCryptoException if there is a problem decrypting or verifying
     *         the payload chunk.
     * @throws MslEncodingException if there is a problem parsing the data.
     * @throws MslMessageException if the payload verification failed.
     * @throws MslInternalException if attempting to access payloads of an
     *         error message.
     * @throws MslException if there is an error uncompressing the data.
     */
    std::shared_ptr<io::ByteArrayInputStream> nextData();

    /**
     * <p>Create new payload chunk.</p>
     *
     * @param ctx the MSL context.
     * @param payloadChunkMo the MSL object.
     * @param cryptoContext the crypto context.
     * @throws MslCryptoException if there is a problem decrypting or verifying
     *         the payload chunk.
     * @throws MslEncodingException if there is a problem parsing the data.
     * @throws MslMessageException if the compression algorithm is not known,
     *         or the payload data is corrupt or missing.
     * @throws MslException if there is an error uncompressing the data.
     */
    std::shared_ptr<PayloadChunk> createPayloadChunk(std::shared_ptr<util::MslContext> ctx,
    		std::shared_ptr<io::MslObject> payloadChunkMo,
    		std::shared_ptr<crypto::ICryptoContext> cryptoContext);

private:
    /** MSL context. */
    std::shared_ptr<util::MslContext> ctx_;
    /** MSL input stream. */
    std::shared_ptr<io::InputStream> source_;
    /** MSL tokenizer. */
    std::shared_ptr<io::MslTokenizer> tokenizer_;

    /** Header. */
    std::shared_ptr<Header> header_;
    /** Payload crypto context. */
    std::shared_ptr<crypto::ICryptoContext> cryptoContext_;
    /** Key exchange crypto context. */
    std::shared_ptr<crypto::ICryptoContext> keyxCryptoContext_;

    /** Current payload sequence number. */
    int64_t payloadSequenceNumber_ = 1;
    /** End of message reached. */
    bool eom_ = false;
    /** Handshake message. -1 if not yet set. */
    int handshake_ = -1;

    /** True if the source input stream should be closed. */
    bool closeSource_ = false;

    /** True if buffering. */
    bool buffering_ = false;
    /**
     * Buffered payload data.
     *
     * This list contains all payload data that has been read since the last
     * call to {@link #mark(int)}.
     */
    std::vector<std::shared_ptr<io::ByteArrayInputStream>> payloads_;
    /** Buffered payload data iterator. Not -1 if reading buffered data. */
    int payloadIterator_ = -1;
    /** Mark read limit. */
    size_t readlimit_ = 0;
    /** Mark read count. */
    size_t readcount_ = 0;
    /** Current payload chunk data. */
    std::shared_ptr<io::ByteArrayInputStream> currentPayload_;

    /** Cached read exception. */
    std::shared_ptr<IOException> readException_;
    /** Aborted. */
    bool aborted_ = false;
};
        
}}} // namespace netflix::msl::msg

#endif
