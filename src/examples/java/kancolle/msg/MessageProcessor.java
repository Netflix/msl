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

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import kancolle.KanColleMslError;

import com.netflix.msl.MslConstants;
import com.netflix.msl.MslMessageException;
import com.netflix.msl.msg.MessageInputStream;
import com.netflix.msl.msg.MessageOutputStream;

/**
 * <p>Read and write application messages.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MessageProcessor {
    /** Newline character. */
    private static final String NEWLINE = System.lineSeparator();
    /** Space character. */
    private static final char SPACE = ' ';
    
    /**
     * <p>Acknowledgements are identifed by the string "ACK".</p>
     * 
     * <p>The message output stream is closed.</p>
     * 
     * @param output message output stream.
     * @throws IOException if there is an error writing the message.
     */
    public static void acknowledge(final MessageOutputStream output) throws IOException {
        output.write(Message.Type.ACK.toString().getBytes(MslConstants.DEFAULT_CHARSET));
        output.close();
    }
    
    /**
     * <p>Pings are identified by the string "PING".</p>
     * 
     * <p>The message output stream is closed.</p>
     * 
     * @param output message output stream.
     * @throws IOException if there is an error writing the message.
     */
    public static void ping(final MessageOutputStream output) throws IOException {
        output.write(Message.Type.PING.toString().getBytes(MslConstants.DEFAULT_CHARSET));
        output.close();
    }
    
    /**
     * <p>Reports are identified by the string "REPORT" followed by the number of
     * records. Each record in the log is sent on its own line prefixed by the line
     * number. e.g.
     * <pre>
     * REPORT 2
     * 1: Set heading 80&deg; at 15 knots.
     * 2: Sighted potential enemy on the horizon and slowed to 10 knots.
     * </pre></p>
     * 
     * <p>The message output stream is closed.</p>
     * 
     * @param output message output stream.
     * @param records report records.
     * @throws IOException if there is an error writing the message.
     */
    public static void report(final MessageOutputStream output, final List<String> records) throws IOException {
        final String header = Message.Type.REPORT + Integer.toString(records.size()) + NEWLINE;
        output.write(header.getBytes(MslConstants.DEFAULT_CHARSET));
        for (int i = 0; i < records.size(); ++i) {
            final String record = Integer.toString(i+1) + ": " + records.get(i) + NEWLINE;
            final byte[] b = record.getBytes(MslConstants.DEFAULT_CHARSET);
            output.write(b);
        }
        output.close();
    }

    /** 
     * <p>Critical reports are identified by the string "CRITICAL" followed by the
     * number of records. Each record in the log is sent on its own line prefixed
     * by the line number. e.g.
     * <pre>
     * CRITICAL 3
     * 1: Engaged enemy at 0746 hours.
     * 2: Enemy destroyed at 0813 hours.
     * 3: 12 casualties: 3 dead, 8 wounded, 1 missing.
     * </pre></p>
     * 
     * <p>The message output stream is closed.</p>
     * 
     * @param output message output stream.
     * @param records critical report records.
     * @throws IOException if there is an error writing the message.
     */
    public static void critical(final MessageOutputStream output, final List<String> records) throws IOException {
        final String header = Message.Type.CRITICAL + Integer.toString(records.size()) + NEWLINE;
        output.write(header.getBytes(MslConstants.DEFAULT_CHARSET));
        for (int i = 0; i < records.size(); ++i) {
            final String record = Integer.toString(i+1) + ": " + records.get(i) + NEWLINE;
            final byte[] b = record.getBytes(MslConstants.DEFAULT_CHARSET);
            output.write(b);
        }
        output.close();
    }
    
    /**
     * <p>Order requests are identified by the string "REQUESTING ORDERS".</p>
     * 
     * <p>The message output stream is closed.</p>
     * 
     * @param output message output stream.
     * @throws IOException if there is an error writing the message.
     */
    public static void requestOrders(final MessageOutputStream output) throws IOException {
        output.write(Message.Type.ORDER_REQUEST.toString().getBytes(MslConstants.DEFAULT_CHARSET));
        output.close();
    }
    
    /**
     * <p>Issued orders are identified by the string "ISSUED ORDERS" followed
     * by the orders. e.g
     * <pre>
     * ISSUED ORDERS
     * Proceed to sector 17 and patrol until further orders are received.
     * </pre></p>
     * 
     * <p>The message output stream is closed.</p>
     * 
     * @param output message output stream.
     * @param orders the orders.
     * @throws IOException if there is an error writing the message.
     */
    public static void issueOrders(final MessageOutputStream output, final String orders) throws IOException {
        final String header = Message.Type.ORDER_RESPONSE + NEWLINE;
        output.write(header.getBytes(MslConstants.DEFAULT_CHARSET));
        output.write(orders.getBytes(MslConstants.DEFAULT_CHARSET));
        output.close();
    }
    
    /**
     * <p>Errors are identified by the string "ERROR" followed by an error
     * message.</p>
     * 
     * <p>The message output stream is closed.</p>
     * 
     * @param output message output stream.
     * @param message the error message.
     * @throws IOException if there is an error writing the message.
     */
    public static void error(final MessageOutputStream output, final String message) throws IOException {
        final String header = Message.Type.ERROR + NEWLINE;
        output.write(header.getBytes(MslConstants.DEFAULT_CHARSET));
        output.write(message.getBytes(MslConstants.DEFAULT_CHARSET));
        output.close();
    }
    
    /**
     * <p>Reads a message off the provided message input stream.</p>
     * 
     * @param in message input stream.
     * @return the parsed message.
     * @throws MslMessageException if the message type is not recognized.
     * @throws IOException if there is an error reading the message.
     */
    public static Message parse(final MessageInputStream in) throws MslMessageException, IOException {
        // Read everything off the input stream.
        final StringBuffer messageBuffer = new StringBuffer();
        while (true) {
            final byte[] buffer = new byte[4096];
            final int bytesRead = in.read(buffer);
            if (bytesRead == -1) {
                in.close();
                break;
            }
            messageBuffer.append(new String(buffer, 0, bytesRead, MslConstants.DEFAULT_CHARSET));
        }
        final String message = messageBuffer.toString();
        
        // Figure out the message type.
        Message.Type type = null;
        for (final Message.Type t : Message.Type.values()) {
            if (message.startsWith(t.toString())) {
                type = t;
                break;
            }
        }
        if (type == null)
            throw new MslMessageException(KanColleMslError.MSG_TYPE_UNKNOWN);
        
        // Parse any contents.
        if (type.hasContents()) {
            // Split on the first line.
            final int newlineIndex = message.indexOf(NEWLINE);
            final String contents = message.substring(newlineIndex+1);
            return new Message(type, contents);    
        }
        
        // Parse any records.
        if (type.hasRecords()) {
            // Split on newlines.
            final String[] lines = message.split(NEWLINE);
            
            // The number of records should appear after the type string.
            final int recordsOffset = type.toString().length() + 1;
            final String countString = lines[0].substring(recordsOffset);
            final int count;
            try {
                count = Integer.parseInt(countString);
            } catch (final NumberFormatException e) {
                throw new MslMessageException(KanColleMslError.MSG_RECORD_COUNT_INVALID, countString, e);
            }
            
            // Make sure we have enough records. Extra records are discarded.
            if (lines.length - 1 < count)
                throw new MslMessageException(KanColleMslError.MSG_RECORDS_TRUNCATED, "expected " + count + "; received " + (lines.length - 1));
            
            // Read each record.
            final List<String> records = new ArrayList<String>();
            for (int i = 1; i <= count; ++i) {
                // Grab the record number.
                final String record = lines[i];
                final int spaceIndex = record.indexOf(SPACE);
                final int number;
                try {
                    number = Integer.parseInt(record.substring(0, spaceIndex));
                } catch (final NumberFormatException e) {
                    throw new MslMessageException(KanColleMslError.MSG_RECORD_NUMBER_MISSING, Integer.toString(i), e);
                }
                
                // Make sure the record number is correct.
                if (number != i)
                    throw new MslMessageException(KanColleMslError.MSG_RECORD_NUMBER_MISMATCH, "expected " + i + "; found " + number);
                
                // Add the record.
                records.add(record);
            }
            
            // Return the message.
            return new Message(type, records);
        }
        
        // Return messages without contents or records.
        return new Message(type);
    }
}
