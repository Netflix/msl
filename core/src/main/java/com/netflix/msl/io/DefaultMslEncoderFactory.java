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
package com.netflix.msl.io;

import java.io.InputStream;
import java.util.Set;

/**
 * <p>Default {@link MslEncoderFactory} implementation that supports the
 * following encoder formats:
 * <ul>
 * <li>JSON: backed by {@code org.json}.</li>
 * </ul>
 * </p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class DefaultMslEncoderFactory extends MslEncoderFactory {
    /* (non-Javadoc)
     * @see com.netflix.msl.io.MslEncoderFactory#getPreferredFormat(java.util.Set)
     */
    public MslEncoderFormat getPreferredFormat(final Set<MslEncoderFormat> formats) {
        // We don't know about any other formats right now.
        return MslEncoderFormat.JSON;
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.io.MslEncoderFactory#generateTokenizer(java.io.InputStream, com.netflix.msl.io.MslEncoderFormat)
     */
    protected MslTokenizer generateTokenizer(final InputStream source, final MslEncoderFormat format) throws MslEncoderException {
        // JSON.
        if (MslEncoderFormat.JSON.equals(format))
            return new JsonMslTokenizer(this, source);
        
        // Unsupported encoder format.
        throw new MslEncoderException("Unsupported encoder format: " + format + ".");
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.io.MslEncoderFactory#parseObject(byte[])
     */
    public MslObject parseObject(final byte[] encoding) throws MslEncoderException {
        // Identify the encoder format.
        final MslEncoderFormat format = parseFormat(encoding);
        
        // JSON.
        if (MslEncoderFormat.JSON.equals(format))
            return new JsonMslObject(this, encoding);
        
        // Unsupported encoder format.
        throw new MslEncoderException("Unsupported encoder format: " + format + ".");
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.io.MslEncoderFactory#encodeObject(com.netflix.msl.io.MslObject, com.netflix.msl.io.MslEncoderFormat)
     */
    public byte[] encodeObject(final MslObject object, final MslEncoderFormat format) throws MslEncoderException {
        // JSON.
        if (MslEncoderFormat.JSON.equals(format))
            return JsonMslObject.getEncoded(this, object);
        
        // Unsupported encoder format.
        throw new MslEncoderException("Unsupported encoder format: " + format + ".");
    }
}
