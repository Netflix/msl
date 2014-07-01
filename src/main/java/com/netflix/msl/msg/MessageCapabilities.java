/**
 * Copyright (c) 2013-2014 Netflix, Inc.  All rights reserved.
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
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONString;

import com.netflix.msl.MslConstants.CompressionAlgorithm;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.util.JsonUtils;

/**
 * <p>The message capabilities identify the features supported by the message
 * sender.</p>
 * 
 * <p>The message capabilities are represented as
 * {@code
 * capabilities = {
 *   "compressionalgos" : [ enum(GZIP|LZW) ],
 *   "languages" : [ "string" ],
 * }} where:
 * <ul>
 * <li>{@code compressionalgos} is the set of supported compression algorithms</li>
 * <li>{@code languages} is the preferred list of BCP-47 languages in descending order</li>
 * </ul></p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MessageCapabilities implements JSONString {
    /** JSON key compression algorithms. */
    private static final String KEY_COMPRESSION_ALGOS = "compressionalgos";
    /** JSON key languages. */
    private static final String KEY_LANGUAGES = "languages";
    
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
        final Set<CompressionAlgorithm> compressionAlgos = new HashSet<CompressionAlgorithm>();
        compressionAlgos.addAll(mc1.compressionAlgos);
        compressionAlgos.retainAll(mc2.compressionAlgos);
        
        // Compute the intersection of languages. This may not respect order.
        final List<String> languages = new ArrayList<String>(mc1.languages);
        languages.retainAll(mc2.languages);
        
        return new MessageCapabilities(compressionAlgos, languages);
    }
    
    /**
     * Create a new message capabilities object with the specified supported
     * features.
     * 
     * @param compressionAlgos supported payload compression algorithms. May be
     *        {@code null}.
     * @param languages preferred languages as BCP-47 codes in descending
     *        order. May be {@code null}.
     */
    public MessageCapabilities(final Set<CompressionAlgorithm> compressionAlgos, final List<String> languages) {
        this.compressionAlgos = Collections.unmodifiableSet(compressionAlgos != null ? compressionAlgos : new HashSet<CompressionAlgorithm>());
        this.languages = Collections.unmodifiableList(languages != null ? languages : new ArrayList<String>());
    }
    
    /**
     * Construct a new message capabilities object from the provided JSON
     * object.
     * 
     * @param capabilitiesJO the JSON object.
     * @throws MslEncodingException if there is an error parsing the JSON.
     */
    public MessageCapabilities(final JSONObject capabilitiesJO) throws MslEncodingException {
        try {
            // Extract compression algorithms.
            final Set<CompressionAlgorithm> compressionAlgos = new HashSet<CompressionAlgorithm>();
            final JSONArray algos = capabilitiesJO.optJSONArray(KEY_COMPRESSION_ALGOS);
            for (int i = 0; algos != null && i < algos.length(); ++i) {
                final String algo = algos.getString(i);
                // Ignore unsupported algorithms.
                try {
                    compressionAlgos.add(CompressionAlgorithm.valueOf(algo));
                } catch (final IllegalArgumentException e) {}
            }
            this.compressionAlgos = Collections.unmodifiableSet(compressionAlgos);
            
            // Extract languages.
            final List<String> languages = new ArrayList<String>();
            final JSONArray langs = capabilitiesJO.optJSONArray(KEY_LANGUAGES);
            for (int i = 0; langs != null && i < langs.length(); ++i)
                languages.add(langs.getString(i));
            this.languages = Collections.unmodifiableList(languages);
        } catch (final JSONException e) {
            throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "capabilities " + capabilitiesJO.toString(), e);
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

    /* (non-Javadoc)
     * @see org.json.JSONString#toJSONString()
     */
    @Override
    public String toJSONString() {
        try {
            final JSONObject jo = new JSONObject();
            jo.put(KEY_COMPRESSION_ALGOS, JsonUtils.createArray(compressionAlgos));
            jo.put(KEY_LANGUAGES, languages);
            return jo.toString();
        } catch (final JSONException e) {
            throw new MslInternalException("Error encoding " + this.getClass().getName() + " JSON.", e);
        }
    }
    
    /* (non-Javadoc)
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return toJSONString();
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
            this.languages.equals(that.languages);
    }

    /* (non-Javadoc)
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        return this.compressionAlgos.hashCode() ^ this.languages.hashCode();
    }

    /** Supported payload compression algorithms. */
    private final Set<CompressionAlgorithm> compressionAlgos;
    /** Preferred languages as BCP-47 codes in descending order. */
    private final List<String> languages;
}
