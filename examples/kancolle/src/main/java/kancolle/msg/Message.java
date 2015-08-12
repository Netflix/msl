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
package kancolle.msg;

import java.util.Collections;
import java.util.List;

/**
 * <p>A message is identified by a type and some contents. Some types of
 * messages have no contents (e.g. ping) while other types may contain multiple
 * records for the contents (e.g. report).</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class Message {
    /**
     * Message type strings.
     */
    public static enum Type {
        /** Acknowledgement message identifier. */
        ACK("ACK", false, false),
        /** Ping message identifier. */
        PING("PING", false, false),
        /** Report message identifier. */
        REPORT("REPORT", false, true),
        /** Critical report message identifier. */
        CRITICAL("CRITICAL", false, true),
        /** Requesting orders message identifier. */
        ORDER_REQUEST("REQUESTING ORDERS", false, false),
        /** Issued orders message identifier. */
        ORDER_RESPONSE("ISSUED ORDERS", true, false),
        /** Error message identifier. */
        ERROR("ERROR", true, false);
        ;
    
        /**
         * Create a new message type with the specified properties.
         * 
         * @param s the string representation.
         * @param contents true if the message type has contents.
         * @param records true if the message type has records.
         */
        private Type(final String s, final boolean contents, final boolean records) {
            this.s = s;
            this.contents = contents;
            this.records = records;
        }
        
        /**
         * @return true if the message type has contents.
         */
        public boolean hasContents() {
            return contents;
        }
        
        /**
         * @return true if the message type has records.
         */
        public boolean hasRecords() {
            return records;
        }
        
        /**
         * @return the string representation of this type.
         */
        public String toString() {
            return s;
        }
        
        /** Message type string representation. */
        private final String s;
        /** Message type has contents. */
        private final boolean contents;
        /** Message type has records. */
        private final boolean records;
    }
    
    /**
     * Create a new message of the specified type.
     * 
     * @param type message type.
     * @throws IllegalArgumentException if the type indicates the message must
     *         have contents or records.
     */
    Message(final Type type) {
        if (type.hasContents() || type.hasRecords())
            throw new IllegalArgumentException("Type " + type + " must have contents or records.");
        this.type = type;
        this.contents = null;
        this.records = null;
    }
    
    /**
     * Create a new message with the specified type and contents. Records will
     * be {@code null}.
     * 
     * @param type message type.
     * @param contents message contents.
     * @throws IllegalArgumentException if the type indicates the message
     *         should not have contents.
     */
    Message(final Type type, final String contents) {
        if (!type.hasContents())
            throw new IllegalArgumentException("Type " + type + " does not have contents.");
        this.type = type;
        this.contents = contents;
        this.records = null;
    }
    
    /**
     * Create a new message with the specified type and records. Contents will
     * be {@code null].
     * 
     * @param type message type.
     * @param records message records. May be empty.
     * @throws IllegalArgumentException if the type indicates the message
     *         should not have records.
     */
    Message(final Type type, final List<String> records) {
        if (!type.hasRecords())
            throw new IllegalArgumentException("Type " + type + " must does not have records.");
        this.type = type;
        this.contents = null;
        this.records = Collections.unmodifiableList(records);
    }
    
    /**
     * @return the message type.
     */
    public Type getType() {
        return type;
    }
    
    /**
     * Return the message contents for issued orders.
     * 
     * @return the message contents, which may be the empty string, or
     *         {@code null} if this type of message does not contain records.
     */
    public String getContents() {
        return contents;
    }
    
    /**
     * Return the message records for reports and critical reports.
     * 
     * @return the message records, which may be empty, or {@code null} if this
     *         type of message does not contain records.
     */
    public List<String> getRecords() {
        return records;
    }
    
    /** Type. */
    private final Type type;
    /** Contents. */
    private final String contents;
    /** Records. */
    private final List<String> records;
}
