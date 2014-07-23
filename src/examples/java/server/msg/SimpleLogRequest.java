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

import java.util.Date;

import org.json.JSONException;
import org.json.JSONObject;

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
    
    /**
     * <p>Create a new log request.</p>
     * 
     * @param identity requesting entity identity.
     * @param user requesting user. May be null.
     * @param data the request data object.
     * @throws SimpleRequestParseException if there is an error parsing the
     *         request data.
     */
    public SimpleLogRequest(final String identity, final SimpleUser user, final JSONObject data) throws SimpleRequestParseException {
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
        System.out.println("Log " + getUser() + "@" + getIdentity() + ": " +
            new Date(timestamp) + " [" + severity.name() + "] " + message);
        
        return new SimpleRespondMessageContext(getIdentity(), false, "success");
    }

    /** Timestamp in seconds since the UNIX epoch. */
    private final long timestamp;
    /** Severity. */
    private final Severity severity;
    /** Message. */
    private final String message;
}
