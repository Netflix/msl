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
package server.msg;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.Map;
import java.util.Set;

import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONString;

import com.netflix.msl.MslConstants;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.msg.MessageHeader;
import com.netflix.msl.msg.MessageInputStream;
import com.netflix.msl.tokens.ServiceToken;

import server.userauth.SimpleUser;

/**
 * <p>Example request type and parser.</p>
 * 
 * <p>Requests are represented as JSON as follows:
 * {@code {
 * request = {
 *   "#mandatory" : [ "type", "data" ],
 *   "type" : "string",
 *   "data" : "object",
 * }
 * }} where:
 * <ul>
 * <li>{@code type} is the request type.</li>
 * <li>{@code data} is the request data.</li>
 * </ul></p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public abstract class SimpleRequest implements JSONString {
    /** JSON key type. */
    private static final String KEY_TYPE = "type";
    /** JSON key data. */
    private static final String KEY_DATA = "data";
    
    /** Request type. */
    public enum Type {
        /** Echo request data. */
        ECHO,
        /** Query for data. */
        QUERY,
        /** Provide log data. */
        LOG,
        /** Return user profile. */
        USER_PROFILE,
        /** Terminate server execution. */
        QUIT,
    }
    
    /**
     * <p>Parse a request from the provided input stream. The requesting entity
     * identity must be provided. The requesting user may be null.</p>
     * 
     * @param identity request entity identity.
     * @param user request user. May be null.
     * @param request request data.
     * @param cryptoContexts service token crypto contexts.
     * @return the parsed request.
     * @throws IOException if there is an error reading from the input stream.
     * @throws SimpleRequestUnknownException if the request cannot be
     *         identified.
     * @throws SimpleRequestParseException if the request data fails to parse
     *         successfully.
     * @throws SimpleRequestUserException if the request type requires a user
     *         but there is none provided.
     */
    public static SimpleRequest parse(final String identity, final SimpleUser user, final MessageInputStream request, final Map<String,ICryptoContext> cryptoContexts) throws SimpleRequestUnknownException, SimpleRequestParseException, SimpleRequestUserException, IOException {
        // Read request JSON.
        final StringBuilder jsonBuilder = new StringBuilder();
        final Reader r = new InputStreamReader(request, MslConstants.DEFAULT_CHARSET);
        try {
            while (true) {
                final char[] buffer = new char[4096];
                final int count = r.read(buffer);
                if (count < 0)
                    break;
                jsonBuilder.append(buffer, 0, count);
            }
        } finally {
            try { r.close(); } catch(final IOException e) {}
        }
        final JSONObject json = new JSONObject(jsonBuilder.toString());
        
        // Parse request.
        final String typeString;
        final JSONObject data;
        try {
            typeString = json.getString(KEY_TYPE);
            data = json.getJSONObject(KEY_DATA);
        } catch (final JSONException e) {
            throw new SimpleRequestParseException("Error parsing request outer structure: " + json.toString(), e);
        }
        
        // Determine type.
        final Type type;
        try {
            type = Type.valueOf(typeString);
        } catch (final IllegalArgumentException e) {
            throw new SimpleRequestUnknownException("Unknown request type " + typeString + ".");
        }
        
        // Return request.
        switch (type) {
            case ECHO:
                return new SimpleEchoRequest(identity, user, data);
            case QUERY:
                return new SimpleQueryRequest(identity, user, data);
            case LOG:
                final MessageHeader header = request.getMessageHeader();
                final Set<ServiceToken> tokens = header.getServiceTokens();
                return new SimpleLogRequest(identity, user, data, tokens, cryptoContexts);
            case USER_PROFILE:
                return new SimpleProfileRequest(identity, user, data);
            case QUIT:
                return new SimpleQuitRequest(identity, user, data);
            default:
                throw new SimpleRequestUnknownException("Request type " + type + " has no request class.");
        }
    }
    
    /**
     * <p>Create a simple request with the provided data.</p>
     * 
     * @param type request type.
     * @param identity request entity identity.
     * @param user request user. May be null.
     */
    protected SimpleRequest(final Type type, final String identity, final SimpleUser user) {
        this.type = type;
        this.identity = identity;
        this.user = user;
    }
    
    /**
     * @return the request type.
     */
    public Type getType() {
        return type;
    }

    /**
     * @return the request entity identity.
     */
    public String getIdentity() {
        return identity;
    }

    /**
     * @return the request user. May be null.
     */
    public SimpleUser getUser() {
        return user;
    }

    /**
     * @return the request data object.
     */
    public abstract JSONObject getData();
    
    /**
     * <p>Executes the operation and returns the response.
     * 
     * @return the response.
     * @throws SimpleRequestUserException if the request type requires a user
     *         but there is none provided.
     * @throws SimpleRequestExecutionException if there is an error executing
     *         the request.
     */
    public abstract SimpleRespondMessageContext execute() throws SimpleRequestUserException, SimpleRequestExecutionException;

    /* (non-Javadoc)
     * @see org.json.JSONString#toJSONString()
     */
    @Override
    public String toJSONString() {
        final JSONObject jo = new JSONObject();
        jo.put(KEY_TYPE, type.name());
        jo.put(KEY_DATA, getData());
        return jo.toString();
    }
    
    /** Request type. */
    private final Type type;
    /** Request entity identity. */
    private final String identity;
    /** Request user. */
    private final SimpleUser user;
}
