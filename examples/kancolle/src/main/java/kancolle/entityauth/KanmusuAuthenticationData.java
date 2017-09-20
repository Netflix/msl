/**
 * Copyright (c) 2014-2017 Netflix, Inc.  All rights reserved.
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
package kancolle.entityauth;

import kancolle.KanColleMslError;

import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslEntityAuthException;
import com.netflix.msl.MslError;
import com.netflix.msl.entityauth.EntityAuthenticationData;
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.io.MslObject;

/**
 * <p>Each Kanmusu ship is identified by a type and name. The unique identity
 * of a ship is equal to the type and name concatenated in that order by a
 * single colon ":" character.</p>
 * 
 * <p>
 * {@code {
 *   "#mandatory" : [ "type", "name" ],
 *   "type" : "string",
 *   "name" : "name",
 * }} where:
 * <ul>
 * <li>{@code type} is the ship type</li>
 * <li>{@code name} is the ship name</li>
 * </ul></p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class KanmusuAuthenticationData extends EntityAuthenticationData {
    /** Key ship type. */
    private static final String KEY_TYPE = "type";
    /** Key ship name. */
    private static final String KEY_NAME = "name";
    
    /** Colon character. */
    private static final String CHAR_COLON = ":";
    
    /**
     * Construct a new Kanmusu authentication data instance with the specified
     * type and name. Colons are not permitted in the type or name.
     * 
     * @param type the ship type.
     * @param name the ship name.
     * @throws IllegalArgumentException if the type or name contains a colon.
     */
    public KanmusuAuthenticationData(final String type, final String name) {
        super(KanColleEntityAuthenticationScheme.KANMUSU);
        
        // Colons are not permitted in the type or name.
        if (type.contains(CHAR_COLON) || name.contains(CHAR_COLON))
            throw new IllegalArgumentException("Colons are not permitted in the type [" + type + "] or name [" + name + "].");
        this.type = type;
        this.name = name;
    }
    
    /**
     * Construct a new Kanmusu authentication data instance from the provided
     * identity.
     * 
     * @param identity the ship identity.
     * @throws IllegalArgumentException if the identity does not consist of a
     *         type and name separated by a single colon.
     * @see #getIdentity()
     */
    public KanmusuAuthenticationData(final String identity) {
        super(KanColleEntityAuthenticationScheme.KANMUSU);
        
        // Split on the colon.
        final String[] parts = identity.split(CHAR_COLON);
        if (parts.length != 2)
            throw new IllegalArgumentException("Identity must consist of a type and name separated by a single colon.");
        this.type = parts[0];
        this.name = parts[1];
    }

    /**
     * Construct a new Kanmusu authentication data instance from the provided
     * MSL object.
     * 
     * @param kanmusuMo the authentication data MSL object.
     * @throws MslEncodingException if there is an error parsing the entity
     *         authentication data.
     * @throws MslEntityAuthException if the type or name includes a colon.
     */
    public KanmusuAuthenticationData(final MslObject kanmusuMo) throws MslEncodingException, MslEntityAuthException {
        super(KanColleEntityAuthenticationScheme.KANMUSU);
        try {
            type = kanmusuMo.getString(KEY_TYPE);
            name = kanmusuMo.getString(KEY_NAME);
        } catch (final MslEncoderException e) {
            throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "kanmusu authdata " + kanmusuMo.toString(), e);
        }
        
        // Colons are not permitted in the type or name.
        if (type.contains(CHAR_COLON) || name.contains(CHAR_COLON))
            throw new MslEntityAuthException(KanColleMslError.KANMUSU_ILLEGAL_IDENTITY, "kanmusu authdata " + kanmusuMo.toString());
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationData#getIdentity()
     */
    @Override
    public String getIdentity() {
        return type + ":" + name;
    }
    
    /**
     * @return the ship type.
     */
    public String getType() {
        return type;
    }
    
    /**
     * @return the ship name.
     */
    public String getName() {
        return name;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationData#getAuthData(com.netflix.msl.io.MslEncoderFactory, com.netflix.msl.io.MslEncoderFormat)
     */
    @Override
    public MslObject getAuthData(final MslEncoderFactory encoder, final MslEncoderFormat format) throws MslEncoderException {
        final MslObject mo = encoder.createObject();
        mo.put(KEY_TYPE, type);
        mo.put(KEY_NAME, name);
        return mo;
    }

    /** Ship type. */
    private final String type;
    /** Ship name. */
    private final String name;
}
