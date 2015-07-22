/**
 * Copyright (c) 2012-2014 Netflix, Inc.  All rights reserved.
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
package com.netflix.msl.msg;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import com.netflix.msl.MslConstants.CompressionAlgorithm;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslException;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.util.MslContext;

/**
 * <p>A MSL message consists of a single MSL header followed by one or more
 * payload chunks carrying application data. Each payload chunk is individually
 * packaged but sequentially ordered. The end of the message is indicated by a
 * payload with no data.</p>
 * 
 * <p>No payload chunks may be included in an error message.</p>
 * 
 * <p>Data is buffered until {@link #flush()} or {@link #close()} is called.
 * At that point a new payload chunk is created and written out. Closing a
 * {@code MessageOutputStream} does not close the destination output stream in
 * case additional MSL messages will be written.</p>
 * 
 * <p>A copy of the payload chunks is kept in-memory and can be retrieved by a
 * a call to {@code getPayloads()} until {@code stopCaching()} is called. This
 * is used to facilitate automatic re-sending of messages.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MessageOutputStream extends OutputStream {
    /**
     * Construct a new error message output stream. The header is output
     * immediately by calling {@code #flush()} on the destination output
     * stream.
     * 
     * @param ctx the MSL context.
     * @param destination MSL output stream.
     * @param charset output stream character set encoding.
     * @param header error header.
     * @throws IOException if there is an error writing the header.
     */
    public MessageOutputStream(final MslContext ctx, final OutputStream destination, final Charset charset, final ErrorHeader header) throws IOException {
        this.destination = destination;
        this.charset = charset;
        this.capabilities = ctx.getMessageCapabilities();
        this.header = header;
        this.compressionAlgo = null;
        this.cryptoContext = null;
        this.destination.write(this.header.toJSONString().getBytes(charset));
        this.destination.flush();
    }

    /**
     * Construct a new message output stream. The header is output
     * immediately by calling {@code #flush()} on the destination output
     * stream. The most preferred compression algorithm supported by the
     * local entity and message header will be used.
     * 
     * @param ctx the MSL context.
     * @param destination MSL output stream.
     * @param charset output stream character set encoding.
     * @param header message header.
     * @param cryptoContext payload data crypto context.
     * @throws IOException if there is an error writing the header.
     */
    public MessageOutputStream(final MslContext ctx, final OutputStream destination, final Charset charset, final MessageHeader header, final ICryptoContext cryptoContext) throws IOException {
        // The supported compression algorithms is the intersection of what the
        // local entity supports and what the remote entity supports.
        final MessageCapabilities capabilities = MessageCapabilities.intersection(ctx.getMessageCapabilities(), header.getMessageCapabilities());
        final CompressionAlgorithm compressionAlgo;
        if (capabilities != null) {
            final Set<CompressionAlgorithm> compressionAlgos = capabilities.getCompressionAlgorithms();
            compressionAlgo = CompressionAlgorithm.getPreferredAlgorithm(compressionAlgos);
        } else {
            compressionAlgo = null;
        }
        
        this.destination = destination;
        this.charset = charset;
        this.capabilities = capabilities;
        this.header = header;
        this.compressionAlgo = compressionAlgo;
        this.cryptoContext = cryptoContext;
        this.destination.write(this.header.toJSONString().getBytes(charset));
        this.destination.flush();
    }
    
    /* (non-Javadoc)
     * @see java.lang.Object#finalize()
     */
    @Override
    protected void finalize() throws Throwable {
        close();
        super.finalize();
    }

    /**
     * Set the payload chunk compression algorithm that will be used for all
     * future payload chunks. This function will flush any buffered data iff
     * the compression algorithm is being changed.
     * 
     * @param compressionAlgo payload chunk compression algorithm. Null for no
     *        compression.
     * @return true if the compression algorithm is supported by the message,
     *         false if it is not.
     * @throws IOException if buffered data could not be flushed. The
     *         compression algorithm will be unchanged.
     * @throws MslInternalException if writing an error message.
     * @see #flush()
     */
    public boolean setCompressionAlgorithm(final CompressionAlgorithm compressionAlgo) throws IOException {
        // Make sure this is not an error message,
        final MessageHeader messageHeader = getMessageHeader();
        if (messageHeader == null)
            throw new MslInternalException("Cannot write payload data for an error message.");
        
        // Make sure the message is capable of using the compression algorithm.
        if (compressionAlgo != null) {
            if (capabilities == null)
                return false;
            final Set<CompressionAlgorithm> compressionAlgos = capabilities.getCompressionAlgorithms();
            if (!compressionAlgos.contains(compressionAlgo))
                return false;
        }
        
        if (this.compressionAlgo != compressionAlgo)
            flush();
        this.compressionAlgo = compressionAlgo;
        return true;
    }
    
    /**
     * @return the message header. Will be null for error messages.
     */
    public MessageHeader getMessageHeader() {
        if (header instanceof MessageHeader)
            return (MessageHeader)header;
        return null;
    }
    
    /**
     * @return the error header. Will be null except for error messages.
     */
    public ErrorHeader getErrorHeader() {
        if (header instanceof ErrorHeader)
            return (ErrorHeader)header;
        return null;
    }
    
    /**
     * Returns the payloads sent so far. Once payload caching is turned off
     * this list will always be empty.
     * 
     * @return an immutable ordered list of the payloads sent so far.
     */
    List<PayloadChunk> getPayloads() {
        return Collections.unmodifiableList(payloads);
    }
    
    /**
     * Turns off caching of any message data (e.g. payloads).
     */
    void stopCaching() {
        caching = false;
        payloads.clear();
    }
    
    /**
     * By default the destination output stream is not closed when this message
     * output stream is closed. If it should be closed then this method can be
     * used to dictate the desired behavior.
     * 
     * @param close true if the destination output stream should be closed,
     *        false if it should not.
     */
    public void closeDestination(final boolean close) {
        this.closeDestination = close;
    }
    
    /* (non-Javadoc)
     * @see java.io.OutputStream#close()
     */
    @Override
    public void close() throws IOException {
        if (closed) return;
        
        // Send a final payload that can be used to identify the end of data.
        // This is done by setting closed equal to true while the current
        // payload not null.
        closed = true;
        flush();
        currentPayload = null;

        // Only close the destination if instructed to do so because we might
        // want to reuse the connection.
        if (closeDestination)
            destination.close();
    }

    /**
     * Flush any buffered data out to the destination. This creates a payload
     * chunk. If there is no buffered data or this is an error message this
     * function does nothing.
     * 
     * @throws IOException if buffered data could not be flushed.
     * @throws MslInternalException if writing an error message.
     * @see java.io.OutputStream#flush()
     */
    @Override
    public void flush() throws IOException {
        // If the current payload is null, we are already closed.
        if (currentPayload == null) return;
        
        // If we are not closed, and there is no data then we have nothing to
        // send.
        if (!closed && currentPayload.size() == 0) return;
        
        // This is a no-op for error messages and handshake messages.
        final MessageHeader messageHeader = getMessageHeader();
        if (messageHeader == null || messageHeader.isHandshake()) return;

        // Otherwise we are closed and need to send any buffered data as the
        // last payload. If there is no buffered data, we still need to send a
        // payload with the end of message flag set.
        try {
            final byte[] data = (currentPayload != null) ? currentPayload.toByteArray() : new byte[0];
            final PayloadChunk chunk = new PayloadChunk(payloadSequenceNumber, messageHeader.getMessageId(), closed, compressionAlgo, data, this.cryptoContext);
            if (caching) payloads.add(chunk);
            destination.write(chunk.toJSONString().getBytes(charset));
            destination.flush();
            ++payloadSequenceNumber;
            
            // If we are closed, get rid of the current payload. This prevents
            // us from sending any more payloads. Otherwise reset it for reuse.
            if (closed)
                currentPayload = null;
            else
                currentPayload.reset();
        } catch (final MslEncodingException e) {
            throw new IOException("Error encoding payload chunk [sequence number " + payloadSequenceNumber + "].", e);
        } catch (final MslCryptoException e) {
            throw new IOException("Error encrypting payload chunk [sequence number " + payloadSequenceNumber + "].", e);
        } catch (final MslException e) {
            throw new IOException("Error compressing payload chunk [sequence number " + payloadSequenceNumber + "].", e);
        }
    }

    /* (non-Javadoc)
     * @see java.io.OutputStream#write(byte[], int, int)
     */
    @Override
    public void write(final byte[] b, final int off, final int len) throws IOException {
        // Fail if closed.
        if (closed)
            throw new IOException("Message output stream already closed.");
        
        // Make sure this is not an error message or handshake message.
        final MessageHeader messageHeader = getMessageHeader();
        if (messageHeader == null)
            throw new MslInternalException("Cannot write payload data for an error message.");
        if (messageHeader.isHandshake())
            throw new MslInternalException("Cannot write payload data for a handshake message.");
        
        // Append data.
        currentPayload.write(b, off, len);
    }

    /* (non-Javadoc)
     * @see java.io.OutputStream#write(byte[])
     */
    @Override
    public void write(byte[] b) throws IOException {
        write(b, 0, b.length);
    }

    /* (non-Javadoc)
     * @see java.io.OutputStream#write(int)
     */
    @Override
    public void write(int b) throws IOException {
        final byte[] ba = new byte[1];
        ba[0] = (byte)(b & 0xFF);
        write(ba);
    }

    /** Destination output stream. */
    private final OutputStream destination;
    /** Output stream character set encoding. */
    private final Charset charset;
    /** Message output stream capabilities. */
    private final MessageCapabilities capabilities;
    
    /** Header. */
    private final Header header;
    /** Payload crypto context. */
    private final ICryptoContext cryptoContext;
    
    /** Paload chunk compression algorithm. */
    private CompressionAlgorithm compressionAlgo;
    /** Current payload sequence number. */
    private long payloadSequenceNumber = 1;
    /** Current payload chunk data. */
    private ByteArrayOutputStream currentPayload = new ByteArrayOutputStream();
    
    /** Stream is closed. */
    private boolean closed = false;
    /** True if the destination output stream should be closed. */
    private boolean closeDestination = false;
    
    /** True if caching data. */
    private boolean caching = true;
    /** Ordered list of sent payloads. */
    private final List<PayloadChunk> payloads = new ArrayList<PayloadChunk>();
}
