/**
 * Copyright (c) 2013-2017 Netflix, Inc.  All rights reserved.
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
import java.util.Random;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import com.netflix.msl.MslConstants;
import com.netflix.msl.MslConstants.CompressionAlgorithm;
import com.netflix.msl.MslError;
import com.netflix.msl.MslException;
import com.netflix.msl.io.LZWInputStream;
import com.netflix.msl.io.LZWOutputStream;

/**
 * Utility methods.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MslUtils {
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
        try {
            switch (compressionAlgo) {
                case GZIP:
                {
                    final ByteArrayOutputStream baos = new ByteArrayOutputStream(data.length);
                    final GZIPOutputStream gzos = new GZIPOutputStream(baos);
                    try {
                        gzos.write(data);
                    } finally {
                        gzos.close();
                    }
                    final byte[] compressed = baos.toByteArray();
                    return (compressed.length < data.length) ? compressed : null;
                }
                case LZW:
                {
                    final ByteArrayOutputStream baos = new ByteArrayOutputStream(data.length);
                    final LZWOutputStream lzwos = new LZWOutputStream(baos);
                    try {
                        lzwos.write(data);
                    } finally {
                        lzwos.close();
                    }
                    final byte[] compressed = baos.toByteArray();
                    return (compressed.length < data.length)? compressed : null; 
                }
                default:
                    throw new MslException(MslError.UNSUPPORTED_COMPRESSION, compressionAlgo.name());
            }
        } catch (final IOException e) {
            final String dataB64 = Base64.encode(data);
            throw new MslException(MslError.COMPRESSION_ERROR, "algo " + compressionAlgo.name() + " data " + dataB64, e);
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
        try {
            switch (compressionAlgo) {
                case GZIP:
                {
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
                case LZW:
                {
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
                default:
                    throw new MslException(MslError.UNSUPPORTED_COMPRESSION, compressionAlgo.name());
            }
        } catch (final IOException e) {
            final String dataB64 = Base64.encode(data);
            throw new MslException(MslError.UNCOMPRESSION_ERROR, "algo " + compressionAlgo.name() + " data " + dataB64, e);
        }
    }

    /**
     * Safely compares two byte arrays to prevent timing attacks.
     * 
     * @param a first array for the comparison.
     * @param b second array for the comparison.
     * @return true if the arrays are equal, false if they are not.
     */
    public static boolean safeEquals(final byte[] a, final byte[] b) {
       if (a.length != b.length)
          return false;
       
       int result = 0;
       for (int i = 0; i < a.length; ++i)
          result |= a[i] ^ b[i];
       return result == 0;
    }
    
    /**
     * Return true if the number is a non-negative power of two. Zero is
     * considered a power of two and will return true.
     * 
     * @param n the number to test.
     * @return true if the number is a non-negative power of two.
     */
    private static boolean isPowerOf2(final long n) {
    		// If the number is a power of two, a binary AND operation between
    		// the number and itself minus one will equal zero.
    		if (n < 0) return false;
    		if (n == 0) return true;
    		return (n & (n - 1)) == 0;
    }
    
    /**
     * Returns a random number between zero and the maximum long value as
     * defined by {@link MslConstants#MAX_LONG_VALUE}, inclusive.
     * 
     * @param ctx MSL context.
     * @return a random number between zero and the maximum long value,
     *         inclusive.
     */
    public static long getRandomLong(final MslContext ctx) {
    		// If the maximum long value is a power of 2, then we can perform a
    		// bitmask on the randomly generated long value to restrict to our
    		// target number space.
    		final boolean isPowerOf2 = MslUtils.isPowerOf2(MslConstants.MAX_LONG_VALUE);
    		
    		// Generate the random value.
    		final Random r = ctx.getRandom();
    		long n = -1;
    		do {
    			n = r.nextLong();
    			
    			// Perform a bitmask if permitted, which will force this loop
    			// to exit immediately.
    			if (isPowerOf2)
    				n &= (MslConstants.MAX_LONG_VALUE - 1);
    		} while (n < 0 || n > MslConstants.MAX_LONG_VALUE);
    		
    		// Return the random value.
    		return n;
    }
}
