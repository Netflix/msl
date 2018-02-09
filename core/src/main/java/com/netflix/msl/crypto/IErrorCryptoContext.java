/**
 * Copyright (c) 2012-2017 Netflix, Inc.  All rights reserved.
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
package com.netflix.msl.crypto;

import com.netflix.msl.MslConstants;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;

/**
 * A specific cryptographic context suitable for sign/verify of ErrorHeader
 *
 * @author Justin Ryan <jryan@netflix.com>
 */
public interface IErrorCryptoContext {

    /**
     * Computes the signature for some data, given an ErrorHeader. The signature may not be a
     * signature proper, but the name suits the concept.
     * 
     * @param data the data.
     * @param encoder MSL encoder factory.
     * @param format MSL encoder format.
     * @param internalCode Internal error code.
     * @param errorCode Response error code.
     * @param recipient Recipient of error
     * @return the signature.
     * @throws MslCryptoException if there is an error computing the signature.
     */
    byte[] sign(final byte[] data, final MslEncoderFactory encoder, final MslEncoderFormat format, int internalCode, MslConstants.ResponseCode errorCode, String recipient) throws MslCryptoException;
}
