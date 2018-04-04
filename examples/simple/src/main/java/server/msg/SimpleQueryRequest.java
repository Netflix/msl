/**
 * Copyright (c) 2014-2018 Netflix, Inc.  All rights reserved.
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
package server.msg;

import org.json.JSONException;
import org.json.JSONObject;

import server.SimpleConstants;
import server.userauth.SimpleUser;

/**
 * <p>Query for a data value. Some data values require a user identity for
 * access.</p>
 * 
 * <p>The request data object is defined as:
 * {@code
 * data = {
 *   "#mandatory" : [ "key" ],
 *   "key" : "string"
 * }} where:
 * <ul>
 * <li>{@code key} is the data key identifying the value.</li>
 * </ul></p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class SimpleQueryRequest extends SimpleRequest {
    /** JSON key key. */
    private static final String KEY_KEY = "key";
    
    /**
     * <p>Create a new query request.</p>
     * 
     * @param identity requesting entity identity.
     * @param user requesting user. May be null.
     * @param data the request data.
     * @throws SimpleRequestParseException if there is an error parsing the
     *         request data.
     */
    public SimpleQueryRequest(final String identity, final SimpleUser user, final JSONObject data) throws SimpleRequestParseException {
        super(Type.QUERY, identity, user);
        try {
            key = data.getString(KEY_KEY);
        } catch (final JSONException e) {
            throw new SimpleRequestParseException("Error parsing query request: " + data.toString() + ".", e);
        }
    }
    
    /**
     * @return the data key.
     */
    public String getKey() {
        return key;
    }

    /* (non-Javadoc)
     * @see server.msg.SimpleRequest#getData()
     */
    @Override
    public JSONObject getData() {
        final JSONObject jo = new JSONObject();
        jo.put(KEY_KEY, key);
        return jo;
    }

    /* (non-Javadoc)
     * @see server.msg.SimpleRequest#execute()
     */
    @Override
    public SimpleRespondMessageContext execute() throws SimpleRequestUserException, SimpleRequestExecutionException {
        // Pull requesting user.
        final SimpleUser user = getUser();
        final String username = (user != null) ? user.toString() : null;
        
        // Identify the requested data.
        for (final String[] data : SimpleConstants.QUERY_DATA) {
            if (data[1].equals(key)) {
                final String response;
                if (data[0] != null && !data[0].equals(username))
                    throw new SimpleRequestUserException("Error: access restricted to user " + data[0] + ".");
                else
                    response = data[2];
                return new SimpleRespondMessageContext(true, response);
            }
        }
        
        // Data key not found.
        throw new SimpleRequestExecutionException("Error: no data found for key " + key + ".");
    }

    /** Data key. */
    private final String key;
}
