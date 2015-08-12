/**
 * Copyright (c) 2014 Netflix, Inc.  All rights reserved.
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

import org.json.JSONException;
import org.json.JSONObject;

import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslException;
import com.netflix.msl.entityauth.EntityAuthenticationData;

/**
 * <p>Each naval port is identified by a callsign. The callsign may not contain
 * a colon ":" character.</p>
 * 
 * <p>In order to authenticate a port uses a secret word from its associated
 * codebook identified by a page and word number. The page and word number
 * should be randomly chosen.</p>
 * 
 * <p>
 * {@code {
 *   "#mandatory" : [ "callsign", "page", "word" ],
 *   "callsign" : "string",
 *   "page" : "number",
 *   "word" : "number",
 * }} where:
 * <ul>
 * <li>{@code callsign} is the port callsign</li>
 * <li>{@code page} is a page number from the port codebook</li>
 * <li>{@code word} is a word number from the identified page of the port codebook</li>
 * </ul></p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class NavalPortAuthenticationData extends EntityAuthenticationData {
    /** Colon character. */
    private static final String CHAR_COLON = ":";
    
    /** JSON key callsign. */
    private static final String KEY_CALLSIGN = "callsign";
    /** JSON key page number. */
    private static final String KEY_PAGE = "page";
    /** JSON key word number. */
    private static final String KEY_WORD = "word";
    
    /**
     * Construct a new naval port authentication data instance with the
     * specified callsign and given page and word number.
     * 
     * @param callsign the port callsign.
     * @param page the codebook page number.
     * @param word the codebook word number.
     * @throws IllegalArgumentException if the callsign contains a colon.
     */
    public NavalPortAuthenticationData(final String callsign, final int page, final int word) {
        super(KanColleEntityAuthenticationScheme.NAVAL_PORT);
        
        // Colons are not permitted in the callsign.
        if (callsign.contains(CHAR_COLON))
            throw new IllegalArgumentException("Colons are not permitted in the callsign [" + callsign + "].");
        this.callsign = callsign;
        this.page = page;
        this.word = word;
    }

    /**
     * Construct a new naval port authentication data instance from the
     * provided JSON object.
     * 
     * @param navalPortJo the authentication data JSON object.
     * @throws MslEncodingException if there is an error parsing the entity
     *         authentication data.
     * @throws MslException if the callsign contains a colon.
     */
    public NavalPortAuthenticationData(final JSONObject navalPortJo) throws MslEncodingException, MslException {
        super(KanColleEntityAuthenticationScheme.NAVAL_PORT);
        try {
            callsign = navalPortJo.getString(KEY_CALLSIGN);
            page = navalPortJo.getInt(KEY_PAGE);
            word = navalPortJo.getInt(KEY_WORD);
        } catch (final JSONException e) {
            throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "naval port authdata " + navalPortJo.toString(), e);
        }
        
        // Colons are not permitted in the callsign.
        if (callsign.contains(CHAR_COLON))
            throw new MslException(KanColleMslError.NAVALPORT_ILLEGAL_IDENTITY, "naval port authdata " + navalPortJo.toString());
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationData#getIdentity()
     */
    @Override
    public String getIdentity() {
        return callsign;
    }
    
    /**
     * @return the codebook page number.
     */
    public int getPage() {
        return page;
    }
    
    /**
     * @return the codebook word number.
     */
    public int getWord() {
        return word;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthenticationData#getAuthData()
     */
    @Override
    public JSONObject getAuthData() throws MslEncodingException {
        try {
            final JSONObject jo = new JSONObject();
            jo.put(KEY_CALLSIGN, callsign);
            jo.put(KEY_PAGE, page);
            jo.put(KEY_WORD, word);
            return jo;
        } catch (final JSONException e) {
            throw new MslEncodingException(MslError.JSON_ENCODE_ERROR, this.getClass().getName(), e);
        }
    }

    /** Port callsign. */
    private final String callsign;
    /** Codebook page number. */
    private final int page;
    /** Codebook word number. */
    private final int word;
}
