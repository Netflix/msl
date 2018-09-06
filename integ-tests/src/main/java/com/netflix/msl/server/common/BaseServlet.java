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
package com.netflix.msl.server.common;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.netflix.msl.MslConstants;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.keyx.KeyExchangeScheme;
import com.netflix.msl.msg.ConsoleFilterStreamFactory;
import com.netflix.msl.msg.MslControl;
import com.netflix.msl.server.configuration.msg.ServerMessageContext;
import com.netflix.msl.server.configuration.tokens.TokenFactoryType;
import com.netflix.msl.server.configuration.util.ServerMslContext;
import com.netflix.msl.userauth.UserAuthenticationScheme;

/**
 * User: skommidi
 * Date: 7/21/14
 */
public class BaseServlet extends HttpServlet {
    private static final long serialVersionUID = -325218339823577479L;
    
    protected static final boolean debug = false;
    protected static final int TIMEOUT = 25000;
    private boolean isNullCryptoContext;
    private boolean setConsoleFilterStreamFactory;
    private EntityAuthenticationScheme entityAuthScheme;
    private int numThreads;
    private TokenFactoryType tokenFactoryType;
    private long initialSequenceNum;
    private final List<EntityAuthenticationScheme> unSupportedEntityAuthFactories;
    private final List<UserAuthenticationScheme> unSupportedUserAuthFactories;
    private final List<KeyExchangeScheme> unSupportedKeyxFactories;
    protected ServerMslContext mslCtx;
    protected ServerMessageContext msgCtx;
    protected MslControl mslCtrl;

    /**
     * @param numThreads
     * @param entityAuthScheme
     * @param tokenFactoryType
     * @param initialSequenceNum
     * @param unSupportedEntityAuthFactories
     * @param unSupportedUserAuthFactories
     * @param unSupportedKeyxFactories
     * @param isNullCryptoContext
     * @param setConsoleFilterStreamFactory
     * @throws MslCryptoException if there is an error signing or creating the
     *         entity authentication data.
     * @throws MslEncodingException if there is an error creating the entity
     *         authentication data.
     * @throws Exception if there is an error configuring the servlet.
     */
    public BaseServlet(final int numThreads, final EntityAuthenticationScheme entityAuthScheme, final TokenFactoryType tokenFactoryType,
                       final long initialSequenceNum,
                       final List<EntityAuthenticationScheme> unSupportedEntityAuthFactories,
                       final List<UserAuthenticationScheme> unSupportedUserAuthFactories, final List<KeyExchangeScheme> unSupportedKeyxFactories,
                       final boolean isNullCryptoContext, final boolean setConsoleFilterStreamFactory) throws Exception {
        this.numThreads = numThreads;
        this.entityAuthScheme = entityAuthScheme;
        this.tokenFactoryType = tokenFactoryType;
        this.initialSequenceNum = initialSequenceNum;
        this.unSupportedEntityAuthFactories = unSupportedEntityAuthFactories;
        this.unSupportedUserAuthFactories = unSupportedUserAuthFactories;
        this.unSupportedKeyxFactories = unSupportedKeyxFactories;
        this.isNullCryptoContext = isNullCryptoContext;
        this.setConsoleFilterStreamFactory = setConsoleFilterStreamFactory;
        configure();
    }

    /**
     * @throws MslCryptoException if there is an error signing or creating the
     *         entity authentication data.
     * @throws MslEncodingException if there is an error creating the entity
     *         authentication data.
     * @throws Exception if there is an error configuring the servlet.
     */
    protected void configure() throws Exception {
        /** MSL control configuration. */
        mslCtrl = new MslControl(numThreads, null, null);
        if(setConsoleFilterStreamFactory) {
            mslCtrl.setFilterFactory(new ConsoleFilterStreamFactory());
        }
        
        /** MSL context configuration. */
        mslCtx = new ServerMslContext(entityAuthScheme, false, tokenFactoryType, initialSequenceNum, unSupportedEntityAuthFactories,
                unSupportedUserAuthFactories, unSupportedKeyxFactories, isNullCryptoContext);
    }

    @Override
    protected void service(final HttpServletRequest request, final HttpServletResponse response) throws ServletException, IOException {
        response.setHeader("Access-Control-Allow-Origin", "*");
        response.setHeader("Access-Control-Allow-Headers", "Content-Type");

        super.service(request, response);
    }

    @Override
    protected void doGet(final HttpServletRequest request, final HttpServletResponse response) throws ServletException, IOException {
        response.setContentType("text/plain");
        final PrintWriter out = response.getWriter();

        @SuppressWarnings("unchecked")
        final
        Map<String, String[]> params = request.getParameterMap();
        for (final Entry<String,String[]> entry : params.entrySet()) {
            try {
                final String key = entry.getKey();
                final String[] value = entry.getValue();
                setPrivateVariable(out, key, value);
            } catch (final Exception e) {
                if (debug)
                    e.printStackTrace();
                out.println(e.getMessage());
            }
        }
        try {
            configure();
        } catch (final Exception e) {
            if (debug)
                e.printStackTrace();
            out.println(e.getMessage());
        }
        out.println(request.getServletPath());
        out.close();
    }

    protected void setPrivateVariable(final PrintWriter out, final String key, final String[] values) throws Exception {
        if (key.equals("numthreads")) {
            this.numThreads = Integer.parseInt(values[0]);
            out.println(key + ": " + values[0]);
        } else if (key.equals("entityauthscheme")) {
            this.entityAuthScheme = EntityAuthenticationScheme.getScheme(values[0]);
            out.println(key + ": " + values[0]);
        } else if (key.equals("tokenfactorytype")) {
            this.tokenFactoryType = TokenFactoryType.valueOf(values[0]);
            out.println(key + ": " + values[0]);
        } else if (key.equals("initialseqnum")) {
            this.initialSequenceNum = Long.parseLong(values[0]);
            out.println(key + ": " + values[0]);
        } else if(key.equals("consoleFilterStreamFactory")) {
            this.setConsoleFilterStreamFactory = Boolean.parseBoolean(values[0]);
            out.println(key + ": " + values[0]);
        } else if(key.equals("nullCryptoContext")) {
            this.isNullCryptoContext = Boolean.parseBoolean(values[0]);
            out.println(key + ":" + values[0]);
        } else if (key.equals("unsupentityauthfact")) {
            this.unSupportedEntityAuthFactories.clear();
            for (final String entityAuth : values) {
                this.unSupportedEntityAuthFactories.add(EntityAuthenticationScheme.getScheme(entityAuth));
                out.println(key + ": " + entityAuth);
            }
        } else if (key.equals("unsupuserauthfact")) {
            this.unSupportedUserAuthFactories.clear();
            for (final String userAuth : values) {
                this.unSupportedUserAuthFactories.add(UserAuthenticationScheme.getScheme(userAuth));
                out.println(key + ": " + userAuth);
            }
        } else if (key.equals("unsupkeyexfact")) {
            this.unSupportedKeyxFactories.clear();
            for (final String keyEx : values) {
                this.unSupportedKeyxFactories.add(KeyExchangeScheme.getScheme(keyEx));
                out.println(key + ": " + keyEx);
            }
        } else {
            throw new Exception("Invalid parameter: " + key);
        }
    }


    protected String getBody(final HttpServletRequest request) throws IOException {
        String body = null;
        final StringBuilder stringBuilder = new StringBuilder();
        BufferedReader bufferedReader = null;

        try {
            final InputStream inputStream = request.getInputStream();
            if (inputStream != null) {
                bufferedReader = new BufferedReader(new InputStreamReader(inputStream, MslConstants.DEFAULT_CHARSET));
                bufferedReader.mark(100000);
                final char[] charBuffer = new char[128];
                int bytesRead = -1;
                while ((bytesRead = bufferedReader.read(charBuffer)) > 0) {
                    stringBuilder.append(charBuffer, 0, bytesRead);
                }
                bufferedReader.reset();
            } else {
                stringBuilder.append("");
            }
        } catch (final IOException ex) {
            throw ex;
        } finally {
            if (bufferedReader != null) {
                try {
                    bufferedReader.close();
                } catch (final IOException ex) {
                    throw ex;
                }
            }
        }

        body = stringBuilder.toString();
        return body;
    }
}
