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
package com.netflix.msl.keyx;

import com.netflix.msl.crypto.ICryptoContext;

/**
 * <p>The wrap crypto context repository provides access to wrapping key crypto
 * contexts and is used by key exchange factories that make use of intermediate
 * wrapping keys to deliver new wrapping key data to the application. The
 * wrapping key data and its corresponding crypto context can then be used in
 * future key request data.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public interface WrapCryptoContextRepository {
    /**
     * Add a new wrapping key crypto context and wrap data. The wrap data
     * should be used in key request data to request a new wrapping key
     * wrapped with this wrapping key.
     * 
     * @param wrapdata wrapping key wrap data.
     * @param cryptoContext wrapping key crypto context.
     */
    public void addCryptoContext(final byte[] wrapdata, final ICryptoContext cryptoContext);
    
    /**
     * Return the wrapping key crypto context identified by the specified
     * wrap data.
     * 
     * @param wrapdata wrapping key wrap data.
     * @return the wrapping key crypto context or null if none exists.
     */
    public ICryptoContext getCryptoContext(final byte[] wrapdata);
    
    /**
     * Remove the wrapping key crypto context identified by the specified
     * key wrap data. This is called after calling
     * {@link #addCryptoContext(byte[], ICryptoContext)} to
     * indicate the old wrapping crypto context should no longer be
     * necessary.
     * 
     * @param wrapdata wrapping key wrap data.
     */
    public void removeCryptoContext(final byte[] wrapdata);
}
