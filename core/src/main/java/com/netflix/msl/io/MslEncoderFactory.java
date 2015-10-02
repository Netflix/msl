/**
 * Copyright (c) 2015 Netflix, Inc.  All rights reserved.
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
package com.netflix.msl.io;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * <p>A factory class for producing {@link MslTokener}, {@link MslObject},
 * and {@link MslArray} instances of various encoding formats.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MslEncoderFactory {
    /**
     * Create a new {@link MslTokenizer}. The encoding format will be
     * determined by inspecting the byte stream identifier located in the first
     * byte.
     * 
     * @param source the binary data to tokenize.
     * @return the {@link MslTokenizer}.
     * @throws MslEncoderException if there is a problem reading the byte
     *         stream identifier or if the encoding format is not supported.
     */
    public MslTokenizer createTokenizer(final InputStream source) throws MslEncoderException {
        final InputStream bufferedSource = source.markSupported() ? source : new BufferedInputStream(source);
        
        // Identify the encoding format.
        final MslEncodingFormat format;
        try {
            bufferedSource.mark(1);
            final byte id = (byte)bufferedSource.read();
            format = MslEncodingFormat.getFormat(id);
            bufferedSource.reset();
        } catch (final IOException e) {
            throw new MslEncoderException("Failure reading the byte stream identifier.", e);
        }
        return createTokenizer(bufferedSource, format);
    }
    
    /**
     * Create a new {@link MslTokenizer} of the specified encoding format.
     * 
     * @param source the binary data to tokenize.
     * @param format the encoding format.
     * @return the {@link MslTokenizer}.
     * @throws MslEncoderException if the encoding format is not supported.
     */
    public MslTokenizer createTokenizer(final InputStream source, final MslEncodingFormat format) throws MslEncoderException {
        // JSON.
        if (MslEncodingFormat.JSON.equals(format)) {
            return new JsonMslTokenizer(source);
        }
        
        // Unsupported encoding format.
        throw new MslEncoderException("Unsupported encoding format: " + format + ".");
    }
    
    /**
     * Create a new {@link MslObject} of the specified encoding format.
     * 
     * @param format the encoding format.
     * @return the {@link MslObject}.
     * @throws MslEncoderException if the encoding format is not supported.
     */
    public MslObject createObject(final MslEncodingFormat format) throws MslEncoderException {
        // JSON.
        if (MslEncodingFormat.JSON.equals(format)) {
            return new JsonMslObject();
        }
        
        // Unsupported encoding format.
        throw new MslEncoderException("Unsupported encoding format: " + format + ".");
    }

    /**
     * Create a new {@link MslArray} of the specified encoding format.
     * 
     * @param format the encoding format.
     * @return the {@link MslArray}.
     * @throws MslEncoderException if the encoding format is not supported.
     */
    public MslArray createArray(final MslEncodingFormat format) throws MslEncoderException {
        // JSON.
        if (MslEncodingFormat.JSON.equals(format)) {
            return new JsonMslArray();
        }
        
        // Unsupported encoding format.
        throw new MslEncoderException("Unsupported encoding format: " + format + ".");
    }
}
