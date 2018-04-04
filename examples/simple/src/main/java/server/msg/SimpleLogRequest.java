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

import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.json.JSONException;
import org.json.JSONObject;

import com.netflix.msl.MslConstants;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.tokens.ServiceToken;

import server.msg.SimpleRespondMessageContext.Token;
import server.userauth.SimpleUser;

/**
 * <p>Request to log a message.</p>
 * 
 * <p>The request data object is defined as:
 * {@code
 * data = {
 *   "#mandatory" : [ "timestamp", "severity", "message" ],
 *   "timestamp" : "number",
 *   "severity" : enum(ERROR|WARN|INFO),
 *   "message" : "string",
 * }} where:
 * <ul>
 * <li>{@code timestamp} is the log message time in seconds since the UNIX epoch.</li>
 * <li>{@code severity} is the log message severity.</li>
 * <li>{@code message} is the log message text.</li>
 * </ul></p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class SimpleLogRequest extends SimpleRequest {
    /** JSON key timestamp. */
    private static final String KEY_TIMESTAMP = "timestamp";
    /** JSON key severity. */
    private static final String KEY_SEVERITY = "severity";
    /** JSON key message. */
    private static final String KEY_MESSAGE = "message";
    
    /** Log message severity. */
    public enum Severity {
        ERROR,
        WARN,
        INFO
    }
    
    /** Log data service token name. */
    public static final String SERVICETOKEN_LOGDATA_NAME = "server.logdata";
    
    /**
     * <p>Create a new log request.</p>
     * 
     * @param identity requesting entity identity.
     * @param user requesting user. May be null.
     * @param data the request data object.
     * @param tokens service tokens.
     * @param cryptoContext service token crypto contexts.
     * @throws SimpleRequestParseException if there is an error parsing the
     *         request data.
     */
    public SimpleLogRequest(final String identity, final SimpleUser user, final JSONObject data, final Set<ServiceToken> tokens, final Map<String,ICryptoContext> cryptoContexts) throws SimpleRequestParseException {
        super(Type.LOG, identity, user);
        final String severityString;
        try {
            timestamp = data.getLong(KEY_TIMESTAMP);
            severityString = data.getString(KEY_SEVERITY);
            message = data.getString(KEY_MESSAGE);
        } catch (final JSONException e) {
            throw new SimpleRequestParseException("Error parsing log request.", e);
        }
        try {
            severity = Severity.valueOf(severityString);
        } catch (final IllegalArgumentException e) {
            throw new SimpleRequestParseException("Unknown severity " + severityString + ".", e);
        }
        String logdata = null;
        for (final ServiceToken token : tokens) {
            if (!token.isDecrypted())
                continue;
            if (SERVICETOKEN_LOGDATA_NAME.equals(token.getName())) {
                logdata = new String(token.getData(), MslConstants.DEFAULT_CHARSET);
                break;
            }
        }
        this.logdata = logdata;
        this.cryptoContexts = Collections.unmodifiableMap(cryptoContexts);
    }
    
    /**
     * <p>Returns the log message timestamp in seconds since the UNIX epoch.</p>
     * 
     * @return the log message timestamp.
     */
    public long getTimestamp() {
        return timestamp;
    }
    
    /**
     * @return the log message severity.
     */
    public Severity getSeverity() {
        return severity;
    }
    
    /**
     * @return the log message.
     */
    public String getMessage() {
        return message;
    }
    
    /* (non-Javadoc)
     * @see server.msg.SimpleRequest#getData()
     */
    @Override
    public JSONObject getData() {
        final JSONObject jo = new JSONObject();
        jo.put(KEY_TIMESTAMP, timestamp);
        jo.put(KEY_SEVERITY, severity.name());
        jo.put(KEY_MESSAGE, message);
        return jo;
    }
    
    /* (non-Javadoc)
     * @see server.msg.SimpleRequest#execute()
     */
    @Override
    public SimpleRespondMessageContext execute() {
        final String newMessage = "Log " + getUser() + "@" + getIdentity() + ": " +
            new Date(timestamp) + " [" + severity.name() + "] " + message;
        final String allMessages = (logdata != null)
            ? logdata + System.lineSeparator() + newMessage
            : newMessage;
        
        System.out.println(newMessage);
        
        final Set<Token> tokens = new HashSet<Token>();
        tokens.add(new Token(SERVICETOKEN_LOGDATA_NAME, allMessages, true, true));
        return new SimpleRespondMessageContext(false, allMessages, tokens, cryptoContexts);
    }

    /** Timestamp in seconds since the UNIX epoch. */
    private final long timestamp;
    /** Severity. */
    private final Severity severity;
    /** Message. */
    private final String message;
    /** Previous log data. */
    private final String logdata;
    
    /** Service token crypto contexts. */
    private final Map<String,ICryptoContext> cryptoContexts;
}
