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

import server.userauth.SimpleUser;

/**
 * <p>Request to echo the request message. The requesting entity identity and
 * user (if any) is also echoed.</p>
 * 
 * <p>The request data object is defined as:
 * {@code
 * data = {
 *   "#mandatory" : [ "message" ],
 *   "message" : "string"
 * }} where:
 * <ul>
 * <li>{@code message} is the message to echo.</li>
 * </ul></p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class SimpleEchoRequest extends SimpleRequest {
    /** JSON key message. */
    private static final String KEY_MESSAGE = "message";
    
    /**
     * <p>Create a new echo request.</p>
     * 
     * @param identity requesting entity identity.
     * @param user requesting user. May be null.
     * @param data the request data object.
     * @throws SimpleRequestParseException if there is an error parsing the
     *         request data.
     */
    public SimpleEchoRequest(final String identity, final SimpleUser user, final JSONObject data) throws SimpleRequestParseException {
        super(Type.ECHO, identity, user);
        try {
            message = data.getString(KEY_MESSAGE);
        } catch (final JSONException e) {
            throw new SimpleRequestParseException("Error parsing echo request.", e);
        }
    }

    /* (non-Javadoc)
     * @see server.msg.SimpleRequest#getData()
     */
    @Override
    public JSONObject getData() {
        final JSONObject jo = new JSONObject();
        jo.put(KEY_MESSAGE, message);
        return jo;
    }

    /* (non-Javadoc)
     * @see server.msg.SimpleRequest#execute()
     */
    @Override
    public SimpleRespondMessageContext execute() {
        final SimpleUser user = getUser();
        final String username = (user != null) ? user.toString() : null;
        final String data = username + "@" + getIdentity() + ": " + message;
        return new SimpleRespondMessageContext(true, data);
    }

    /** Message to echo. */
    private final String message;
}
