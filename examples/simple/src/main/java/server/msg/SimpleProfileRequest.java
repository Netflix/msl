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

import org.json.JSONObject;

import server.SimpleConstants;
import server.userauth.SimpleUser;

/**
 * <p>Request to return a user profile.</p>
 * 
 * <p>The request data object is defined as an empty JSON object.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class SimpleProfileRequest extends SimpleRequest {
    /**
     * <p>Create a new user profile request.</p>
     * 
     * @param identity requesting entity identity.
     * @param user requesting user.
     * @param data the request data.
     * @throws SimpleRequestUserException if the user is null.
     */
    public SimpleProfileRequest(final String identity, final SimpleUser user, final JSONObject data) throws SimpleRequestUserException {
        super(Type.USER_PROFILE, identity, user);
        if (user == null)
            throw new SimpleRequestUserException("A user is required for the user profile request.");
    }

    /* (non-Javadoc)
     * @see server.msg.SimpleRequest#getData()
     */
    @Override
    public JSONObject getData() {
        return new JSONObject();
    }

    @Override
    public SimpleRespondMessageContext execute() {
        final String response;
        
        // The request must come from a user.
        final SimpleUser user = getUser();
        if (user == null) {
            response = "Error: log in to access your user profile.";
        }
        
        // Grab the profile.
        else {
            final String username = user.toString();
            final JSONObject profile = SimpleConstants.PROFILES.get(username);
            if (profile == null) {
                response = "Error: no profile found for " + username + ".";
            } else {
                response = profile.toString(4);
            }
        }
        
        // Return the response.
        return new SimpleRespondMessageContext(true, response);
    }
}
