/**
 * Copyright (c) 2017 Netflix, Inc.  All rights reserved.
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
package com.netflix.msl.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import com.netflix.msl.MslConstants.CompressionAlgorithm;
import com.netflix.msl.MslError;
import com.netflix.msl.MslException;
import com.netflix.msl.io.LZWInputStream;
import com.netflix.msl.io.LZWOutputStream;

/**
 * <p>Data compression and uncompression. Can be configured with a backing
 * implementation.</p>
 * 
 * <p>This class is thread-safe.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MslCompression {
    /** Registered compression implementations. */
    private static Map<CompressionAlgorithm,CompressionImpl> impls = new ConcurrentHashMap<CompressionAlgorithm,CompressionImpl>();
    
    /**
     * <p>A data compression implementation. Implementations must be thread-
     * safe.</p>
     */
    public static interface CompressionImpl {
        /**
         * Compress the provided data.
         * 
         * @param data the data to compress.
         * @return the compressed data.
         * @throws IOException if there is an error compressing the data.
         */
        public byte[] compress(final byte[] data) throws IOException;
        
        /**
         * Uncompress the provided data.
         * 
         * @param data the data to uncompress.
         * @return the uncompressed data.
         * @throws IOException if there is an error uncompressing the data.
         */
        public byte[] uncompress(final byte[] data) throws IOException;
    }
    
    /**
     * Default GZIP compression implementation.
     */
    private static class GzipCompressionImpl implements CompressionImpl {
        /* (non-Javadoc)
         * @see com.netflix.msl.util.MslCompression.CompressionImpl#compress(byte[])
         */
        @Override
        public byte[] compress(final byte[] data) throws IOException {
            final ByteArrayOutputStream baos = new ByteArrayOutputStream(data.length);
            final GZIPOutputStream gzos = new GZIPOutputStream(baos);
            try {
                gzos.write(data);
            } finally {
                gzos.close();
            }
            return baos.toByteArray();
        }
        
        /* (non-Javadoc)
         * @see com.netflix.msl.util.MslCompression.CompressionImpl#uncompress(byte[])
         */
        @Override
        public byte[] uncompress(final byte[] data) throws IOException {
            final ByteArrayInputStream bais = new ByteArrayInputStream(data);
            final GZIPInputStream gzis = new GZIPInputStream(bais);
            try {
                final byte[] buffer = new byte[data.length];
                final ByteArrayOutputStream baos = new ByteArrayOutputStream(data.length);
                while (buffer.length > 0) {
                    final int bytesRead = gzis.read(buffer);
                    if (bytesRead == -1) break;
                    baos.write(buffer, 0, bytesRead);
                }
                return baos.toByteArray();
            } finally {
                gzis.close();
            }
        }
    }
    
    /**
     * Default LZW compression implementation.
     */
    private static class LzwCompressionImpl implements CompressionImpl {
        /* (non-Javadoc)
         * @see com.netflix.msl.util.MslCompression.CompressionImpl#compress(byte[])
         */
        @Override
        public byte[] compress(final byte[] data) throws IOException {
            final ByteArrayOutputStream baos = new ByteArrayOutputStream(data.length);
            final LZWOutputStream lzwos = new LZWOutputStream(baos);
            try {
                lzwos.write(data);
            } finally {
                lzwos.close();
            }
            return baos.toByteArray();
        }
        
        /* (non-Javadoc)
         * @see com.netflix.msl.util.MslCompression.CompressionImpl#uncompress(byte[])
         */
        @Override
        public byte[] uncompress(final byte[] data) throws IOException {
            final ByteArrayInputStream bais = new ByteArrayInputStream(data);
            final LZWInputStream lzwis = new LZWInputStream(bais);
            try {
                final byte[] buffer = new byte[data.length];
                final ByteArrayOutputStream baos = new ByteArrayOutputStream(data.length);
                while (buffer.length > 0) {
                    final int bytesRead = lzwis.read(buffer);
                    if (bytesRead == -1) break;
                    baos.write(buffer, 0, bytesRead);
                }
                return baos.toByteArray();
            } finally {
                lzwis.close();
            }
        }
    }
    
    static {
        MslCompression.register(CompressionAlgorithm.GZIP, new GzipCompressionImpl());
        MslCompression.register(CompressionAlgorithm.LZW, new LzwCompressionImpl());
    }
    
    /**
     * <p>Register a compression algorithm implementation. Pass {@code null} to
     * remove an implementation.</p>
     * 
     * @param algo the compression algorithm.
     * @param impl the data compression implementation. May be {@code null}.
     */
    public static void register(final CompressionAlgorithm algo, final CompressionImpl impl) {
        if (impl == null)
            impls.remove(algo);
        else
            impls.put(algo, impl);
    }

    /**
     * Compress the provided data using the specified compression algorithm.
     * 
     * @param compressionAlgo the compression algorithm.
     * @param data the data to compress.
     * @return the compressed data or null if the compressed data would be larger than the
     *         uncompressed data.
     * @throws MslException if there is an error compressing the data.
     */
    public static byte[] compress(final CompressionAlgorithm compressionAlgo, final byte[] data) throws MslException {
        final CompressionImpl impl = impls.get(compressionAlgo);
        if (impl == null)
            throw new MslException(MslError.UNSUPPORTED_COMPRESSION, compressionAlgo.name());
        try {
            final byte[] compressed = impl.compress(data);
            return (compressed.length < data.length) ? compressed : null;
        } catch (final IOException e) {
            throw new MslException(MslError.COMPRESSION_ERROR, "algo " + compressionAlgo.name(), e);
        }
    }
    
    /**
     * Uncompress the provided data using the specified compression algorithm.
     * 
     * @param compressionAlgo the compression algorithm.
     * @param data the data to uncompress.
     * @return the uncompressed data.
     * @throws MslException if there is an error uncompressing the data.
     */
    public static byte[] uncompress(final CompressionAlgorithm compressionAlgo, final byte[] data) throws MslException {
        final CompressionImpl impl = impls.get(compressionAlgo);
        if (impl == null)
            throw new MslException(MslError.UNSUPPORTED_COMPRESSION, compressionAlgo.name());
        try {
            return impl.uncompress(data);
        } catch (final IOException e) {
            throw new MslException(MslError.UNCOMPRESSION_ERROR, "algo " + compressionAlgo.name(), e);
        }
    }
}