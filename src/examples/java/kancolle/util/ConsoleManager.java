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
package kancolle.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import kancolle.msg.Message;
import kancolle.msg.Message.Type;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.msg.ErrorHeader;

/**
 * <p>A thread-safe interactive console manager.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class ConsoleManager extends Thread {
    /**
     * <p>Output a message.</p>
     * 
     * @param author outputting author.
     * @param message message.
     */
    public void message(final String author, final Message message) {
        // Output the type followed by any contents or records.
        final Type type = message.getType();
        final StringBuilder text = new StringBuilder(type.toString());
        if (type.hasContents()) {
            text.append(System.lineSeparator() + message.getContents());
        } else if (type.hasRecords()) {
            for (final String record : message.getRecords())
                text.append(System.lineSeparator() + record);
        }
        out(author, text.toString());
    }
    
    /**
     * <p>Output an error header.</p>
     * 
     * @param author outputting author.
     * @param error error header.
     */
    public void error(final String author, final ErrorHeader error) {
        // Extract sender.
        String sender;
        try {
            sender = error.getEntityAuthenticationData().getIdentity();
        } catch (final MslCryptoException e) {
            sender = e.getMessage();
        }
        
        // Build error string.
        final String userMessage = error.getUserMessage();
        final String text = "Sender[" + sender + "]" +
            error.getErrorCode() + " (" + error.getInternalCode() + ") " +
            error.getErrorMessage() +
            ((userMessage != null) ? " | " + userMessage : "");
        
        // Output error.
        out(author, text);
    }
    
    /**
     * <p>Output some text to the console.</p>
     * 
     * @param author outputting author.
     * @param text text to output.
     */
    public void out(final String author, final String text) {
        io.lock();
        try {
            final String s = "[" + author + "] " + text;
            output.add(s);
            work.signal();
        } finally {
            io.unlock();
        }
    }
    
    /**
     * <p>Request some text from the console.</p>
     * 
     * @param author requesting author.
     * @param text text prompt.
     * @return the entered text.
     * @throws InterruptedException if interrupted while waiting for input.
     */
    public String in(final String author, final String text) throws InterruptedException {
        io.lock();
        try {
            // Prompt for input.
            prompt = "[" + author + "] " + text + ": ";
            work.signal();
            
            // Grab captured input.
            while (input == null)
                captured.await();
            final String entry = input;
            prompt = null;
            input = null;
            return entry;
        } finally {
            io.unlock();
        }
    }
    
    @Override
    public void run() {
        io.lock();
        try {
            while (true) {
                // Wait for work.
                while (output.size() == 0 && prompt == null)
                    work.await();
                
                // Dump all queued output.
                for (final String s : output)
                    System.out.println(s);
                System.out.flush();
                output.clear();
                
                // Prompt for any input.
                if (prompt != null) {
                    System.out.print(prompt);
                    final BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
                    input = br.readLine();
                    captured.signal();
                }
            }
        } catch (final InterruptedException e) {
            e.printStackTrace(System.err);
        } catch (final IOException e) {
            e.printStackTrace(System.err);
        } finally {
            io.unlock();
        }
    }
    
    /** Queued output. */
    private final List<String> output = new ArrayList<String>();
    /** Input prompt. */
    private String prompt = null;
    /** Captured input. */
    private String input = null;
    
    /** I/O lock. */
    private final Lock io = new ReentrantLock();
    /** Queued output or an input prompt. */
    private final Condition work = io.newCondition();
    /** Captured input. */
    private final Condition captured = io.newCondition();
}
