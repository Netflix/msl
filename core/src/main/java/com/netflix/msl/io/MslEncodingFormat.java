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

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

/**
 * <p>MSL encoding formats.</p>
 * 
 * <p>The format name is used to uniquely identify encoding formats.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MslEncodingFormat {
    /** Map of names onto formats. */
    private static Map<String,MslEncodingFormat> formatsByName = new HashMap<String,MslEncodingFormat>();
    /** Map of identifiers onto formats. */
    private static Map<Byte,MslEncodingFormat> formatsById = new HashMap<Byte,MslEncodingFormat>();
    
    /** JSON. */
    public static final MslEncodingFormat JSON = new MslEncodingFormat("JSON", (byte)'{');
    
    /**
     * Define an encoding format with the specified name and byte stream
     * identifier.
     * 
     * @param name the encoding format name.
     * @param identifier the byte stream identifier.
     */
    protected MslEncodingFormat(final String name, final byte identifier) {
        this.name = name;
        this.identifier = identifier;
        
        // Add this format to the map.
        synchronized (formatsByName) {
            formatsByName.put(name, this);
        }
        synchronized (formatsById) {
            formatsById.put(Byte.valueOf(identifier), this);
        }
    }
    
    /**
     * @param name the encoding format name.
     * @return the encoding format identified by the specified name or
     *         {@code null} if there is none.
     */
    public static MslEncodingFormat getFormat(final String name) {
        return formatsByName.get(name);
    }
    
    /**
     * @param name the encoding format identifier.
     * @return the encoding format identified by the specified identifier or
     *         {@code null} if there is none.
     */
    public static MslEncodingFormat getFormat(final byte identifier) {
        return formatsById.get(Byte.valueOf(identifier));
    }
    
    /**
     * @return all known encoding formats.
     */
    public static Collection<MslEncodingFormat> values() {
        return formatsByName.values();
    }
    
    /**
     * @return the format identifier.
     */
    public String name() {
        return name;
    }
    
    /**
     * @return the byte stream identifier.
     */
    public byte identifier() {
        return identifier;
    }
    
    /* (non-Javadoc)
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return name();
    }
    
    /* (non-Javadoc)
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        return name.hashCode() ^ Byte.valueOf(identifier).hashCode();
    }

    /* (non-Javadoc)
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @Override
    public boolean equals(final Object obj) {
        if (obj == this) return true;
        if (!(obj instanceof MslEncodingFormat)) return false;
        final MslEncodingFormat that = (MslEncodingFormat)obj;
        return this.name.equals(that.name) && this.identifier == that.identifier;
    }
    
    /** Name. */
    private final String name;
    /** Byte stream identifier. */
    private final byte identifier;
}
