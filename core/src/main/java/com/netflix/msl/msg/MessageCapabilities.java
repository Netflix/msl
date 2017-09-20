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
package com.netflix.msl.msg;

import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.netflix.msl.MslConstants.CompressionAlgorithm;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;
import com.netflix.msl.io.MslArray;
import com.netflix.msl.io.MslEncodable;
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.io.MslObject;

/**
 * <p>The message capabilities identify the features supported by the message
 * sender.</p>
 * 
 * <p>The message capabilities are represented as
 * {@code
 * capabilities = {
 *   "compressionalgos" : [ enum(GZIP|LZW) ],
 *   "languages" : [ "string" ],
 *   "encoderformats" : [ "string" ],
 * }} where:
 * <ul>
 * <li>{@code compressionalgos} is the set of supported compression algorithms</li>
 * <li>{@code languages} is the preferred list of BCP-47 languages in descending order</li>
 * <li>{@code encoderformats} is the preferred list of MSL encoder formats in descending order</li>
 * </ul></p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MessageCapabilities implements MslEncodable {
    /** Key compression algorithms. */
    private static final String KEY_COMPRESSION_ALGOS = "compressionalgos";
    /** Key languages. */
    private static final String KEY_LANGUAGES = "languages";
    /** Key encoder formats. */
    private static final String KEY_ENCODER_FORMATS = "encoderformats";
    
    /**
     * Computes and returns the intersection of two message capabilities.
     * 
     * @param mc1 first message capabilities. May be {@code null}.
     * @param mc2 second message capabilities. May be {@code null}.
     * @return the intersection of message capabilities or {@code null} if one
     *         of the message capabilities is {@code null}.
     */
    public static MessageCapabilities intersection(final MessageCapabilities mc1, final MessageCapabilities mc2) {
        if (mc1 == null || mc2 == null)
            return null;
        
        // Compute the intersection of compression algorithms.
        final Set<CompressionAlgorithm> compressionAlgos = EnumSet.noneOf(CompressionAlgorithm.class);
        compressionAlgos.addAll(mc1.compressionAlgos);
        compressionAlgos.retainAll(mc2.compressionAlgos);
        
        // Compute the intersection of languages. This may not respect order.
        final List<String> languages = new ArrayList<String>(mc1.languages);
        languages.retainAll(mc2.languages);
        
        // Compute the intersection of encoder formats. This may not respect
        // order.
        final Set<MslEncoderFormat> encoderFormats = new HashSet<MslEncoderFormat>();
        encoderFormats.addAll(mc1.encoderFormats);
        encoderFormats.retainAll(mc2.encoderFormats);
        
        return new MessageCapabilities(compressionAlgos, languages, encoderFormats);
    }
    
    /**
     * Create a new message capabilities object with the specified supported
     * features.
     * 
     * @param compressionAlgos supported payload compression algorithms. May be
     *        {@code null}.
     * @param languages preferred languages as BCP-47 codes in descending
     *        order. May be {@code null}.
     * @param encoderFormats supported encoder formats. May be {@code null}.
     */
    public MessageCapabilities(final Set<CompressionAlgorithm> compressionAlgos, final List<String> languages, final Set<MslEncoderFormat> encoderFormats) {
        this.compressionAlgos = Collections.unmodifiableSet(compressionAlgos != null ? compressionAlgos : EnumSet.noneOf(CompressionAlgorithm.class));
        this.languages = Collections.unmodifiableList(languages != null ? languages : new ArrayList<String>());
        this.encoderFormats = Collections.unmodifiableSet(encoderFormats != null ? encoderFormats : new HashSet<MslEncoderFormat>());
    }
    
    /**
     * Construct a new message capabilities object from the provided MSL
     * object.
     * 
     * @param capabilitiesMo the MSL object.
     * @throws MslEncodingException if there is an error parsing the data.
     */
    public MessageCapabilities(final MslObject capabilitiesMo) throws MslEncodingException {
        try {
            // Extract compression algorithms.
            final Set<CompressionAlgorithm> compressionAlgos = EnumSet.noneOf(CompressionAlgorithm.class);
            final MslArray algos = capabilitiesMo.optMslArray(KEY_COMPRESSION_ALGOS);
            for (int i = 0; algos != null && i < algos.size(); ++i) {
                final String algo = algos.getString(i);
                // Ignore unsupported algorithms.
                try {
                    compressionAlgos.add(CompressionAlgorithm.valueOf(algo));
                } catch (final IllegalArgumentException e) {}
            }
            this.compressionAlgos = Collections.unmodifiableSet(compressionAlgos);
            
            // Extract languages.
            final List<String> languages = new ArrayList<String>();
            final MslArray langs = capabilitiesMo.optMslArray(KEY_LANGUAGES);
            for (int i = 0; langs != null && i < langs.size(); ++i)
                languages.add(langs.getString(i));
            this.languages = Collections.unmodifiableList(languages);
            
            // Extract encoder formats.
            final Set<MslEncoderFormat> encoderFormats = new HashSet<MslEncoderFormat>();
            final MslArray formats = capabilitiesMo.optMslArray(KEY_ENCODER_FORMATS);
            for (int i = 0; formats != null && i < formats.size(); ++i) {
                final String format = formats.getString(i);
                final MslEncoderFormat encoderFormat = MslEncoderFormat.getFormat(format);
                // Ignore unsupported formats.
                if (encoderFormat != null)
                    encoderFormats.add(encoderFormat);
            }
            this.encoderFormats = Collections.unmodifiableSet(encoderFormats);
        } catch (final MslEncoderException e) {
            throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "capabilities " + capabilitiesMo, e);
        }
    }
    
    /**
     * @return the supported compression algorithms.
     */
    public Set<CompressionAlgorithm> getCompressionAlgorithms() {
        return this.compressionAlgos;
    }
    
    /**
     * @return the preferred languages as BCP-47 codes in descending order.
     */
    public List<String> getLanguages() {
        return this.languages;
    }
    
    /**
     * @return the supported encoder formats.
     */
    public Set<MslEncoderFormat> getEncoderFormats() {
        return this.encoderFormats;
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.io.MslEncodable#toMslEncoding(com.netflix.msl.io.MslEncoderFactory, com.netflix.msl.io.MslEncoderFormat)
     */
    @Override
    public byte[] toMslEncoding(final MslEncoderFactory encoder, final MslEncoderFormat format) throws MslEncoderException {
        final MslObject mo = encoder.createObject();
        mo.put(KEY_COMPRESSION_ALGOS, encoder.createArray(compressionAlgos));
        mo.put(KEY_LANGUAGES, languages);
        final MslArray formats = encoder.createArray();
        for (final MslEncoderFormat encoderFormat : encoderFormats)
            formats.put(-1, encoderFormat.name());
        mo.put(KEY_ENCODER_FORMATS, formats);
        return encoder.encodeObject(mo, format);
    }

    /* (non-Javadoc)
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @Override
    public boolean equals(final Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof MessageCapabilities)) return false;
        final MessageCapabilities that = (MessageCapabilities)obj;
        return this.compressionAlgos.equals(that.compressionAlgos) &&
            this.languages.equals(that.languages) &&
            this.encoderFormats.equals(that.encoderFormats);
    }

    /* (non-Javadoc)
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        return this.compressionAlgos.hashCode() ^ this.languages.hashCode() ^ this.encoderFormats.hashCode();
    }
    
    /** Supported payload compression algorithms. */
    private final Set<CompressionAlgorithm> compressionAlgos;
    /** Preferred languages as BCP-47 codes in descending order. */
    private final List<String> languages;
    /** Supported encoder formats. */
    private final Set<MslEncoderFormat> encoderFormats;
}
