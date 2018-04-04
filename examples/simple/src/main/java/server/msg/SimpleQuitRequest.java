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
 * <p>Request to terminate the server. Only the server administrator is
 * permitted to execute this request.</p>
 * 
 * <p>The request data object is defined as an empty JSON object.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class SimpleQuitRequest extends SimpleRequest {
    /**
     * <p>Create a new quit request.</p>
     * 
     * @param identity requesting entity identity.
     * @param user requesting user. May be null.
     * @param data
     */
    public SimpleQuitRequest(final String identity, final SimpleUser user, final JSONObject data) {
        super(Type.QUIT, identity, user);
    }

    /* (non-Javadoc)
     * @see server.msg.SimpleRequest#getData()
     */
    @Override
    public JSONObject getData() {
        return new JSONObject();
    }

    /* (non-Javadoc)
     * @see server.msg.SimpleRequest#execute()
     */
    @Override
    public SimpleRespondMessageContext execute() throws SimpleRequestUserException {
        final String response;
        
        // The request must come from the administrator.
        final SimpleUser user = getUser();
        if (user == null || !SimpleConstants.ADMIN_USERNAME.equals(user.getUserId())) {
            throw new SimpleRequestUserException("Error: only the administrator may terminate the server.");
        } else {
            response = "Terminating server.";
        }

        // Return the response.
        return new SimpleRespondMessageContext(true, response);
    }
}
