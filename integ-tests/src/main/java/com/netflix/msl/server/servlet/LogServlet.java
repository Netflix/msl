/**
 * Copyright (c) 2017 Netflix, Inc.  All rights reserved.
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
package com.netflix.msl.server.servlet;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Writer;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.msg.MessageHeader;
import com.netflix.msl.msg.MessageInputStream;
import com.netflix.msl.server.common.ReceiveServlet;
import com.netflix.msl.server.configuration.tokens.TokenFactoryType;

/**
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class LogServlet extends ReceiveServlet {
    private static final long serialVersionUID = 1030383316461016611L;
    
    /** Report the log message query string. */
    public static final String REPORT = "report";
    
    /** Most recently received log message. */
    private static String message = "";
    
    /**
     * <p>Create a new log servlet that will log any received application data
     * to stdout.</p>
     * 
     * @throws MslCryptoException if there is an error signing or creating the
     *         entity authentication data or an error creating a key
     * @throws MslEncodingException if there is an error creating the entity
     *         authentication data.
     * @throws MslKeyExchangeException if there is an error accessing Diffie-
     *         Hellman parameters.
     * @throws NoSuchAlgorithmException if a key generation algorithm is not
     *         found.
     * @throws InvalidAlgorithmParameterException if key generation parameters
     *         are invalid.
     */
    public LogServlet() throws Exception {
        super(EntityAuthenticationScheme.RSA, TokenFactoryType.ACCEPT_NON_REPLAYABLE_ID, 0,
            null, null, null, null, null, false, false);
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.server.common.BaseServlet#doGet(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
     */
    @Override
    protected void doGet(final HttpServletRequest request, final HttpServletResponse response) throws ServletException, IOException {
        final String query = request.getQueryString();
        if (REPORT.equals(query)) {
            response.setContentType("text/plain");
            final Writer out = response.getWriter();
            out.write(message);
            out.close();
        } else {
            super.doGet(request, response);
        }
    }

    @Override
    protected void receive(final MessageInputStream mis) {
        // Ignore error messages.
        final MessageHeader header = mis.getMessageHeader();
        if (header == null) return;
        
        try {
            // Log the application data.
            final InputStreamReader reader = new InputStreamReader(mis);
            final StringBuffer sb = new StringBuffer();
            final char[] buffer = new char[1 << 16];
            while (true) {
                final int count = reader.read(buffer);
                if (count == -1) break;
                sb.append(buffer, 0, count);
            }
            message = sb.toString();
            System.out.println("LOG: [" + message + "]");
        } catch (final IOException e) {
            if (debug) e.printStackTrace(System.out);
        } finally {
            if (mis != null)
                try { mis.close(); } catch (final IOException e) {}
        }
    }
}
