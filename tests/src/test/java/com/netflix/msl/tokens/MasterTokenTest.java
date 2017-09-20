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
package com.netflix.msl.tokens;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.UnsupportedEncodingException;
import java.util.Date;

import javax.crypto.SecretKey;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;

import com.netflix.msl.MslConstants;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslException;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.crypto.JcaAlgorithm;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.entityauth.MockPresharedAuthenticationFactory;
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.io.MslEncoderUtils;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.test.ExpectedMslException;
import com.netflix.msl.util.MockMslContext;
import com.netflix.msl.util.MslContext;
import com.netflix.msl.util.MslTestUtils;

/**
 * Master token unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MasterTokenTest {
	/** MSL encoder format. */
	private static final MslEncoderFormat ENCODER_FORMAT = MslEncoderFormat.JSON;

    /** Milliseconds per second. */
    private static final long MILLISECONDS_PER_SECOND = 1000;
    
    /** Key token data. */
    private static final String KEY_TOKENDATA = "tokendata";
    /** Key signature. */
    private static final String KEY_SIGNATURE = "signature";

    // tokendata
    /** Key renewal window timestamp. */
    private static final String KEY_RENEWAL_WINDOW = "renewalwindow";
    /** Key expiration timestamp. */
    private static final String KEY_EXPIRATION = "expiration";
    /** Key sequence number. */
    private static final String KEY_SEQUENCE_NUMBER = "sequencenumber";
    /** Key serial number. */
    private static final String KEY_SERIAL_NUMBER = "serialnumber";
    /** Key session data. */
    private static final String KEY_SESSIONDATA = "sessiondata";
    
    // sessiondata
    /** Key issuer data. */
    private static final String KEY_ISSUER_DATA = "issuerdata";
    /** Key identity. */
    private static final String KEY_IDENTITY = "identity";
    /** Key symmetric encryption key. */
    private static final String KEY_ENCRYPTION_KEY = "encryptionkey";
    /** Key encryption algorithm. */
    private static final String KEY_ENCRYPTION_ALGORITHM = "encryptionalgorithm";
    /** Key symmetric HMAC key. */
    private static final String KEY_HMAC_KEY = "hmackey";
    /** Key signature key. */
    private static final String KEY_SIGNATURE_KEY = "signaturekey";
    /** Key signature algorithm. */
    private static final String KEY_SIGNATURE_ALGORITHM = "signaturealgorithm";
    
    private static final Date RENEWAL_WINDOW = new Date(System.currentTimeMillis() + 60000);
    private static final Date EXPIRATION = new Date(System.currentTimeMillis() + 120000);
    private static final long SEQUENCE_NUMBER = 1;
    private static final long SERIAL_NUMBER = 42;
    private static MslObject ISSUER_DATA;
    private static final String IDENTITY = MockPresharedAuthenticationFactory.PSK_ESN;
    private static final SecretKey ENCRYPTION_KEY = MockPresharedAuthenticationFactory.KPE;
    private static final SecretKey SIGNATURE_KEY = MockPresharedAuthenticationFactory.KPH;
    
    private static long incrementSequenceNumber(final long seqNo, final long amount) {
        if (seqNo - MslConstants.MAX_LONG_VALUE + amount <= 0)
            return seqNo + amount;
        return seqNo - MslConstants.MAX_LONG_VALUE - 1 + amount;
    }
    
    private static long decrementSequenceNumber(final long seqNo, final long amount) {
        if (seqNo - amount >= 0)
            return seqNo - amount;
        return MslConstants.MAX_LONG_VALUE - amount - 1 + seqNo;
    }

    @Rule
    public ExpectedMslException thrown = ExpectedMslException.none();
    
    @BeforeClass
    public static void setup() throws MslEncodingException, MslCryptoException, MslEncoderException {
        ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
        encoder = ctx.getMslEncoderFactory();
        ISSUER_DATA = encoder.parseObject("{ 'issuerid' : 17 }".getBytes());
    }
    
    @AfterClass
    public static void teardown() {
        encoder = null;
        ctx = null;
    }
    
    @Test
    public void ctors() throws MslEncoderException, MslException {
        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        assertTrue(masterToken.isDecrypted());
        assertTrue(masterToken.isVerified());
        assertFalse(masterToken.isRenewable(null));
        assertFalse(masterToken.isExpired(null));
        assertFalse(masterToken.isNewerThan(masterToken));
        assertArrayEquals(ENCRYPTION_KEY.getEncoded(), masterToken.getEncryptionKey().getEncoded());
        assertEquals(EXPIRATION.getTime() / MILLISECONDS_PER_SECOND, masterToken.getExpiration().getTime() / MILLISECONDS_PER_SECOND);
        assertArrayEquals(SIGNATURE_KEY.getEncoded(), masterToken.getSignatureKey().getEncoded());
        assertEquals(IDENTITY, masterToken.getIdentity());
        assertTrue(MslEncoderUtils.equalObjects(ISSUER_DATA, masterToken.getIssuerData()));
        assertEquals(RENEWAL_WINDOW.getTime() / MILLISECONDS_PER_SECOND, masterToken.getRenewalWindow().getTime() / MILLISECONDS_PER_SECOND);
        assertEquals(SEQUENCE_NUMBER, masterToken.getSequenceNumber());
        assertEquals(SERIAL_NUMBER, masterToken.getSerialNumber());
        final byte[] encode = masterToken.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(encode);
        
        final MslObject mo = encoder.parseObject(encode);
        final MasterToken moMasterToken = new MasterToken(ctx, mo);
        assertEquals(masterToken.isDecrypted(), moMasterToken.isDecrypted());
        assertEquals(masterToken.isVerified(), moMasterToken.isVerified());
        assertEquals(masterToken.isRenewable(null), moMasterToken.isRenewable(null));
        assertEquals(masterToken.isExpired(null), moMasterToken.isExpired(null));
        assertFalse(moMasterToken.isNewerThan(masterToken));
        assertFalse(masterToken.isNewerThan(moMasterToken));
        assertArrayEquals(masterToken.getEncryptionKey().getEncoded(), moMasterToken.getEncryptionKey().getEncoded());
        assertEquals(masterToken.getExpiration().getTime() / MILLISECONDS_PER_SECOND, moMasterToken.getExpiration().getTime() / MILLISECONDS_PER_SECOND);
        assertArrayEquals(masterToken.getSignatureKey().getEncoded(), moMasterToken.getSignatureKey().getEncoded());
        assertEquals(masterToken.getIdentity(), moMasterToken.getIdentity());
        assertTrue(MslEncoderUtils.equalObjects(masterToken.getIssuerData(), moMasterToken.getIssuerData()));
        assertEquals(masterToken.getRenewalWindow().getTime() / MILLISECONDS_PER_SECOND, moMasterToken.getRenewalWindow().getTime() / MILLISECONDS_PER_SECOND);
        assertEquals(masterToken.getSequenceNumber(), moMasterToken.getSequenceNumber());
        assertEquals(masterToken.getSerialNumber(), moMasterToken.getSerialNumber());
        final byte[] moEncode = moMasterToken.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(moEncode);
        assertArrayEquals(encode, moEncode);
    }
    
    @Test(expected = MslInternalException.class)
    public void negativeSequenceNumberCtor() throws MslEncodingException, MslCryptoException {
        final long sequenceNumber = -1;
        new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, sequenceNumber, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
    }
    
    @Test(expected = MslInternalException.class)
    public void tooLargeSequenceNumberCtor() throws MslEncodingException, MslCryptoException {
        final long sequenceNumber = MslConstants.MAX_LONG_VALUE + 1;
        new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, sequenceNumber, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
    }
    
    @Test(expected = MslInternalException.class)
    public void negativeSerialNumberCtor() throws MslEncodingException, MslCryptoException {
        final long serialNumber = -1;
        new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, serialNumber, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
    }
    
    @Test(expected = MslInternalException.class)
    public void tooLargeSerialNumberCtor() throws MslEncodingException, MslCryptoException {
        final long serialNumber = MslConstants.MAX_LONG_VALUE + 1;
        new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, serialNumber, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
    }
    
    @Test(expected = MslInternalException.class)
    public void inconsistentExpiration() throws MslException, MslEncoderException {
        final Date expiration = new Date(System.currentTimeMillis() - 1);
        final Date renewalWindow = new Date();
        assertTrue(expiration.before(renewalWindow));
        new MasterToken(ctx, renewalWindow, expiration, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
    }
    
    @Test
    public void inconsistentExpirationParse() throws MslException, MslEncoderException, UnsupportedEncodingException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.MASTERTOKEN_EXPIRES_BEFORE_RENEWAL);

        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final byte[] encode = masterToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);
        tokendataMo.put(KEY_EXPIRATION, System.currentTimeMillis() / MILLISECONDS_PER_SECOND - 1);
        tokendataMo.put(KEY_RENEWAL_WINDOW, System.currentTimeMillis() / MILLISECONDS_PER_SECOND);
        mo.put(KEY_TOKENDATA, encoder.encodeObject(tokendataMo, ENCODER_FORMAT));
        
        new MasterToken(ctx, mo);
    }
    
    @Test
    public void nullIssuerData() throws MslEncoderException, MslException {
        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, null, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        assertNull(masterToken.getIssuerData());
        
        final byte[] encode = masterToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        final MasterToken moMasterToken = new MasterToken(ctx, mo);
        assertNull(moMasterToken.getIssuerData());
    }
    
    @Test
    public void missingTokendata() throws MslEncoderException, MslException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);

        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final byte[] encode = masterToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);

        assertNotNull(mo.remove(KEY_TOKENDATA));

        new MasterToken(ctx, mo);
    }
    
    @Test(expected = MslEncodingException.class)
    public void invalidTokendata() throws MslEncoderException, MslException {
        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final byte[] encode = masterToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        ++tokendata[0];
        mo.put(KEY_TOKENDATA, tokendata);
        
        new MasterToken(ctx, mo);
    }
    
    @Test
    public void missingSignature() throws MslEncoderException, MslException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);

        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final byte[] encode = masterToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        assertNotNull(mo.remove(KEY_SIGNATURE));
        
        new MasterToken(ctx, mo);
    }
    
    @Test
    public void missingRenewalWindow() throws MslEncoderException, MslException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MASTERTOKEN_TOKENDATA_PARSE_ERROR);

        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final byte[] encode = masterToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);
        assertNotNull(tokendataMo.remove(KEY_RENEWAL_WINDOW));
        mo.put(KEY_TOKENDATA, encoder.encodeObject(tokendataMo, ENCODER_FORMAT));
        
        new MasterToken(ctx, mo);
    }
    
    @Test
    public void invalidRenewalWindow() throws MslEncoderException, MslException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MASTERTOKEN_TOKENDATA_PARSE_ERROR);

        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final byte[] encode = masterToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);
        tokendataMo.put(KEY_RENEWAL_WINDOW, "x");
        mo.put(KEY_TOKENDATA, encoder.encodeObject(tokendataMo, ENCODER_FORMAT));
        
        new MasterToken(ctx, mo);
    }
    
    @Test
    public void missingExpiration() throws MslEncoderException, MslException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MASTERTOKEN_TOKENDATA_PARSE_ERROR);

        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final byte[] encode = masterToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);
        assertNotNull(tokendataMo.remove(KEY_EXPIRATION));
        mo.put(KEY_TOKENDATA, encoder.encodeObject(tokendataMo, ENCODER_FORMAT));
        
        new MasterToken(ctx, mo);
    }
    
    @Test
    public void invalidExpiration() throws MslEncoderException, MslException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MASTERTOKEN_TOKENDATA_PARSE_ERROR);

        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final byte[] encode = masterToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);
        tokendataMo.put(KEY_EXPIRATION, "x");
        mo.put(KEY_TOKENDATA, encoder.encodeObject(tokendataMo, ENCODER_FORMAT));
        
        new MasterToken(ctx, mo);
    }
    
    @Test
    public void missingSequenceNumber() throws MslEncoderException, MslException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MASTERTOKEN_TOKENDATA_PARSE_ERROR);

        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final byte[] encode = masterToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);
        assertNotNull(tokendataMo.remove(KEY_SEQUENCE_NUMBER));
        mo.put(KEY_TOKENDATA, encoder.encodeObject(tokendataMo, ENCODER_FORMAT));
        
        new MasterToken(ctx, mo);
    }
    
    @Test
    public void invalidSequenceNumber() throws MslEncoderException, MslException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MASTERTOKEN_TOKENDATA_PARSE_ERROR);

        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final byte[] encode = masterToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);
        tokendataMo.put(KEY_SEQUENCE_NUMBER, "x");
        mo.put(KEY_TOKENDATA, encoder.encodeObject(tokendataMo, ENCODER_FORMAT));
        
        new MasterToken(ctx, mo);
    }
    
    @Test
    public void negativeSequenceNumber() throws MslEncodingException, MslCryptoException, MslEncoderException, MslException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.MASTERTOKEN_SEQUENCE_NUMBER_OUT_OF_RANGE);

        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final byte[] encode = masterToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);
        tokendataMo.put(KEY_SEQUENCE_NUMBER, -1);
        mo.put(KEY_TOKENDATA, encoder.encodeObject(tokendataMo, ENCODER_FORMAT));
        
        new MasterToken(ctx, mo);
    }
    
    @Test
    public void tooLargeSequenceNumber() throws MslEncodingException, MslCryptoException, MslEncoderException, MslException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.MASTERTOKEN_SEQUENCE_NUMBER_OUT_OF_RANGE);

        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final byte[] encode = masterToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);
        tokendataMo.put(KEY_SEQUENCE_NUMBER, MslConstants.MAX_LONG_VALUE + 1);
        mo.put(KEY_TOKENDATA, encoder.encodeObject(tokendataMo, ENCODER_FORMAT));
        
        new MasterToken(ctx, mo);
    }
    
    @Test
    public void missingSerialNumber() throws MslEncoderException, MslException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MASTERTOKEN_TOKENDATA_PARSE_ERROR);

        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final byte[] encode = masterToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);
        assertNotNull(tokendataMo.remove(KEY_SERIAL_NUMBER));
        mo.put(KEY_TOKENDATA, encoder.encodeObject(tokendataMo, ENCODER_FORMAT));
        
        new MasterToken(ctx, mo);
    }
    
    @Test
    public void invalidSerialNumber() throws MslEncoderException, MslException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MASTERTOKEN_TOKENDATA_PARSE_ERROR);

        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final byte[] encode = masterToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);
        tokendataMo.put(KEY_SERIAL_NUMBER, "x");
        mo.put(KEY_TOKENDATA, encoder.encodeObject(tokendataMo, ENCODER_FORMAT));
        
        new MasterToken(ctx, mo);
    }
    
    @Test
    public void negativeSerialNumber() throws MslEncodingException, MslCryptoException, MslEncoderException, MslException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.MASTERTOKEN_SERIAL_NUMBER_OUT_OF_RANGE);

        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final byte[] encode = masterToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);
        tokendataMo.put(KEY_SERIAL_NUMBER, -1);
        mo.put(KEY_TOKENDATA, encoder.encodeObject(tokendataMo, ENCODER_FORMAT));
        
        new MasterToken(ctx, mo);
    }
    
    @Test
    public void tooLargeSerialNumber() throws MslEncodingException, MslCryptoException, MslEncoderException, MslException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.MASTERTOKEN_SERIAL_NUMBER_OUT_OF_RANGE);

        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final byte[] encode = masterToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);
        tokendataMo.put(KEY_SERIAL_NUMBER, MslConstants.MAX_LONG_VALUE + 1);
        mo.put(KEY_TOKENDATA, encoder.encodeObject(tokendataMo, ENCODER_FORMAT));
        
        new MasterToken(ctx, mo);
    }
    
    @Test
    public void missingSessiondata() throws MslEncoderException, MslException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MASTERTOKEN_TOKENDATA_PARSE_ERROR);

        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final byte[] encode = masterToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);
        assertNotNull(tokendataMo.remove(KEY_SESSIONDATA));
        mo.put(KEY_TOKENDATA, encoder.encodeObject(tokendataMo, ENCODER_FORMAT));
        
        new MasterToken(ctx, mo);
    }
    
    @Test
    public void invalidSessiondata() throws UnsupportedEncodingException, MslEncoderException, MslException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MASTERTOKEN_TOKENDATA_PARSE_ERROR);

        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final byte[] encode = masterToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);
        tokendataMo.put(KEY_SESSIONDATA, "x");
        
        final ICryptoContext cryptoContext = ctx.getMslCryptoContext();
        final byte[] modifiedTokendata = encoder.encodeObject(tokendataMo, ENCODER_FORMAT);
        final byte[] signature = cryptoContext.sign(modifiedTokendata, encoder, ENCODER_FORMAT);
        mo.put(KEY_TOKENDATA, modifiedTokendata);
        mo.put(KEY_SIGNATURE, signature);
        
        new MasterToken(ctx, mo);
    }
    
    @Test
    public void emptySessiondata() throws UnsupportedEncodingException, MslEncoderException, MslException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.MASTERTOKEN_SESSIONDATA_MISSING);

        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final byte[] encode = masterToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);
        
        final ICryptoContext cryptoContext = ctx.getMslCryptoContext();
        final byte[] ciphertext = new byte[0];
        tokendataMo.put(KEY_SESSIONDATA, ciphertext);
        final byte[] modifiedTokendata = encoder.encodeObject(tokendataMo, ENCODER_FORMAT);
        final byte[] signature = cryptoContext.sign(modifiedTokendata, encoder, ENCODER_FORMAT);
        mo.put(KEY_TOKENDATA, modifiedTokendata);
        mo.put(KEY_SIGNATURE, signature);
        
        new MasterToken(ctx, mo);
    }
    
    @Test(expected = MslCryptoException.class)
    public void corruptSessiondata() throws MslEncoderException, MslException, UnsupportedEncodingException {
        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final byte[] encode = masterToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        // This is testing session data that is verified but corrupt.
        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);
        final byte[] sessiondata = tokendataMo.getBytes(KEY_SESSIONDATA);
        ++sessiondata[sessiondata.length-1];
        tokendataMo.put(KEY_SESSIONDATA, sessiondata);
        
        final ICryptoContext cryptoContext = ctx.getMslCryptoContext();
        final byte[] modifiedTokendata = encoder.encodeObject(tokendataMo, ENCODER_FORMAT);
        final byte[] signature = cryptoContext.sign(modifiedTokendata, encoder, ENCODER_FORMAT);
        mo.put(KEY_TOKENDATA, modifiedTokendata);
        mo.put(KEY_SIGNATURE, signature);
        
        new MasterToken(ctx, mo);
    }
    
    @Test
    public void notVerified() throws MslEncoderException, MslException {
        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final byte[] encode = masterToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        final byte[] signature = mo.getBytes(KEY_SIGNATURE);
        ++signature[0];
        mo.put(KEY_SIGNATURE, signature);
        
        final MasterToken moMasterToken = new MasterToken(ctx, mo);
        assertFalse(moMasterToken.isDecrypted());
        assertFalse(moMasterToken.isVerified());
        assertTrue(moMasterToken.isRenewable(null));
        assertFalse(moMasterToken.isExpired(null));
        assertFalse(moMasterToken.isNewerThan(masterToken));
        assertFalse(masterToken.isNewerThan(moMasterToken));
        assertNull(moMasterToken.getEncryptionKey());
        assertEquals(masterToken.getExpiration().getTime() / MILLISECONDS_PER_SECOND, moMasterToken.getExpiration().getTime() / MILLISECONDS_PER_SECOND);
        assertNull(moMasterToken.getSignatureKey());
        assertNull(moMasterToken.getIdentity());
        assertNull(moMasterToken.getIssuerData());
        assertEquals(masterToken.getRenewalWindow().getTime() / MILLISECONDS_PER_SECOND, moMasterToken.getRenewalWindow().getTime() / MILLISECONDS_PER_SECOND);
        assertEquals(masterToken.getSequenceNumber(), moMasterToken.getSequenceNumber());
        assertEquals(masterToken.getSerialNumber(), moMasterToken.getSerialNumber());
        final byte[] moEncode = moMasterToken.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(moEncode);
        assertFalse(encode.equals(moEncode));
    }
    
    @Test
    public void invalidIssuerData() throws MslEncoderException, MslException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MASTERTOKEN_SESSIONDATA_PARSE_ERROR);

        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final byte[] encode = masterToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        final ICryptoContext cryptoContext = ctx.getMslCryptoContext();
        
        // Before modifying the session data we need to decrypt it.
        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);
        final byte[] ciphertext = tokendataMo.getBytes(KEY_SESSIONDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject sessiondataMo = encoder.parseObject(plaintext);
        
        // After modifying the session data we need to encrypt it.
        sessiondataMo.put(KEY_ISSUER_DATA, "x");
        final byte[] sessiondata = cryptoContext.encrypt(encoder.encodeObject(sessiondataMo, ENCODER_FORMAT), encoder, ENCODER_FORMAT);
        tokendataMo.put(KEY_SESSIONDATA, sessiondata);
        
        // The tokendata must be signed otherwise the session data will not be
        // processed.
        final byte[] modifiedTokendata = encoder.encodeObject(tokendataMo, ENCODER_FORMAT);
        final byte[] signature = cryptoContext.sign(modifiedTokendata, encoder, ENCODER_FORMAT);
        mo.put(KEY_TOKENDATA, modifiedTokendata);
        mo.put(KEY_SIGNATURE, signature);
        
        new MasterToken(ctx, mo);
    }
    
    @Test
    public void missingIdentity() throws MslEncoderException, MslException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MASTERTOKEN_SESSIONDATA_PARSE_ERROR);

        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final byte[] encode = masterToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        final ICryptoContext cryptoContext = ctx.getMslCryptoContext();
        
        // Before modifying the session data we need to decrypt it.
        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);
        final byte[] ciphertext = tokendataMo.getBytes(KEY_SESSIONDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject sessiondataMo = encoder.parseObject(plaintext);
        
        // After modifying the session data we need to encrypt it.
        assertNotNull(sessiondataMo.remove(KEY_IDENTITY));
        final byte[] sessiondata = cryptoContext.encrypt(encoder.encodeObject(sessiondataMo, ENCODER_FORMAT), encoder, ENCODER_FORMAT);
        tokendataMo.put(KEY_SESSIONDATA, sessiondata);
        
        // The tokendata must be signed otherwise the session data will not be
        // processed.
        final byte[] modifiedTokendata = encoder.encodeObject(tokendataMo, ENCODER_FORMAT);
        final byte[] signature = cryptoContext.sign(modifiedTokendata, encoder, ENCODER_FORMAT);
        mo.put(KEY_TOKENDATA, modifiedTokendata);
        mo.put(KEY_SIGNATURE, signature);
        
        new MasterToken(ctx, mo);
    }
    
    @Test
    public void missingEncryptionKey() throws MslEncoderException, MslException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MASTERTOKEN_SESSIONDATA_PARSE_ERROR);

        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final byte[] encode = masterToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        final ICryptoContext cryptoContext = ctx.getMslCryptoContext();
        
        // Before modifying the session data we need to decrypt it.
        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);
        final byte[] ciphertext = tokendataMo.getBytes(KEY_SESSIONDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject sessiondataMo = encoder.parseObject(plaintext);
        
        // After modifying the session data we need to encrypt it.
        assertNotNull(sessiondataMo.remove(KEY_ENCRYPTION_KEY));
        final byte[] sessiondata = cryptoContext.encrypt(encoder.encodeObject(sessiondataMo, ENCODER_FORMAT), encoder, ENCODER_FORMAT);
        tokendataMo.put(KEY_SESSIONDATA, sessiondata);
        
        // The tokendata must be signed otherwise the session data will not be
        // processed.
        final byte[] modifiedTokendata = encoder.encodeObject(tokendataMo, ENCODER_FORMAT);
        final byte[] signature = cryptoContext.sign(modifiedTokendata, encoder, ENCODER_FORMAT);
        mo.put(KEY_TOKENDATA, modifiedTokendata);
        mo.put(KEY_SIGNATURE, signature);
        
        new MasterToken(ctx, mo);
    }

    @Test
    public void invalidEncryptionKey() throws MslEncoderException, MslException, UnsupportedEncodingException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.MASTERTOKEN_KEY_CREATION_ERROR);

        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final byte[] encode = masterToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        final ICryptoContext cryptoContext = ctx.getMslCryptoContext();
        
        // Before modifying the session data we need to decrypt it.
        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);
        final byte[] ciphertext = tokendataMo.getBytes(KEY_SESSIONDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject sessiondataMo = encoder.parseObject(plaintext);
        
        // After modifying the session data we need to encrypt it.
        sessiondataMo.put(KEY_ENCRYPTION_KEY, "");
        final byte[] sessiondata = cryptoContext.encrypt(encoder.encodeObject(sessiondataMo, ENCODER_FORMAT), encoder, ENCODER_FORMAT);
        tokendataMo.put(KEY_SESSIONDATA, sessiondata);
        
        // The tokendata must be signed otherwise the session data will not be
        // processed.
        final byte[] modifiedTokendata = encoder.encodeObject(tokendataMo, ENCODER_FORMAT);
        final byte[] signature = cryptoContext.sign(modifiedTokendata, encoder, ENCODER_FORMAT);
        mo.put(KEY_TOKENDATA, modifiedTokendata);
        mo.put(KEY_SIGNATURE, signature);
        
        new MasterToken(ctx, mo);
    }
    
    @Test
    public void missingEncryptionAlgorithm() throws MslEncodingException, MslCryptoException, MslException, MslEncoderException {
        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final byte[] encode = masterToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        final ICryptoContext cryptoContext = ctx.getMslCryptoContext();
        
        // Before modifying the session data we need to decrypt it.
        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);
        final byte[] ciphertext = tokendataMo.getBytes(KEY_SESSIONDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject sessiondataMo = encoder.parseObject(plaintext);
        
        // After modifying the session data we need to encrypt it.
        assertNotNull(sessiondataMo.remove(KEY_ENCRYPTION_ALGORITHM));
        final byte[] sessiondata = cryptoContext.encrypt(encoder.encodeObject(sessiondataMo, ENCODER_FORMAT), encoder, ENCODER_FORMAT);
        tokendataMo.put(KEY_SESSIONDATA, sessiondata);
        
        // The tokendata must be signed otherwise the session data will not be
        // processed.
        final byte[] modifiedTokendata = encoder.encodeObject(tokendataMo, ENCODER_FORMAT);
        final byte[] signature = cryptoContext.sign(modifiedTokendata, encoder, ENCODER_FORMAT);
        mo.put(KEY_TOKENDATA, modifiedTokendata);
        mo.put(KEY_SIGNATURE, signature);
        
        // Confirm default algorithm.
        final MasterToken moMasterToken = new MasterToken(ctx, mo);
        final SecretKey moEncryptionKey = moMasterToken.getEncryptionKey();
        assertEquals(JcaAlgorithm.AES, moEncryptionKey.getAlgorithm());
    }
    
    @Test
    public void invalidEncryptionAlgorithm() throws MslEncodingException, MslCryptoException, MslException, MslEncoderException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.UNIDENTIFIED_ALGORITHM);
        
        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final byte[] encode = masterToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        final ICryptoContext cryptoContext = ctx.getMslCryptoContext();
        
        // Before modifying the session data we need to decrypt it.
        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);
        final byte[] ciphertext = tokendataMo.getBytes(KEY_SESSIONDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject sessiondataMo = encoder.parseObject(plaintext);
        
        // After modifying the session data we need to encrypt it.
        sessiondataMo.put(KEY_ENCRYPTION_ALGORITHM, "x");
        final byte[] sessiondata = cryptoContext.encrypt(encoder.encodeObject(sessiondataMo, ENCODER_FORMAT), encoder, ENCODER_FORMAT);
        tokendataMo.put(KEY_SESSIONDATA, sessiondata);
        
        // The tokendata must be signed otherwise the session data will not be
        // processed.
        final byte[] modifiedTokendata = encoder.encodeObject(tokendataMo, ENCODER_FORMAT);
        final byte[] signature = cryptoContext.sign(modifiedTokendata, encoder, ENCODER_FORMAT);
        mo.put(KEY_TOKENDATA, modifiedTokendata);
        mo.put(KEY_SIGNATURE, signature);
        
        new MasterToken(ctx, mo);
    }
    
    @Test
    public void missingHmacKey() throws MslEncodingException, MslCryptoException, MslException, MslEncoderException {
        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final byte[] encode = masterToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        final ICryptoContext cryptoContext = ctx.getMslCryptoContext();
        
        // Before modifying the session data we need to decrypt it.
        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);
        final byte[] ciphertext = tokendataMo.getBytes(KEY_SESSIONDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject sessiondataMo = encoder.parseObject(plaintext);
        
        // After modifying the session data we need to encrypt it.
        assertNotNull(sessiondataMo.remove(KEY_HMAC_KEY));
        final byte[] sessiondata = cryptoContext.encrypt(encoder.encodeObject(sessiondataMo, ENCODER_FORMAT), encoder, ENCODER_FORMAT);
        tokendataMo.put(KEY_SESSIONDATA, sessiondata);
        
        // The tokendata must be signed otherwise the session data will not be
        // processed.
        final byte[] modifiedTokendata = encoder.encodeObject(tokendataMo, ENCODER_FORMAT);
        final byte[] signature = cryptoContext.sign(modifiedTokendata, encoder, ENCODER_FORMAT);
        mo.put(KEY_TOKENDATA, modifiedTokendata);
        mo.put(KEY_SIGNATURE, signature);
        
        // Confirm signature key.
        final MasterToken moMasterToken = new MasterToken(ctx, mo);
        final SecretKey moSignatureKey = moMasterToken.getSignatureKey();
        assertArrayEquals(masterToken.getSignatureKey().getEncoded(), moSignatureKey.getEncoded());
    }
    
    @Test
    public void missingSignatureKey() throws MslEncodingException, MslCryptoException, MslException, MslEncoderException {
        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final byte[] encode = masterToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        final ICryptoContext cryptoContext = ctx.getMslCryptoContext();
        
        // Before modifying the session data we need to decrypt it.
        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);
        final byte[] ciphertext = tokendataMo.getBytes(KEY_SESSIONDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject sessiondataMo = encoder.parseObject(plaintext);
        
        // After modifying the session data we need to encrypt it.
        assertNotNull(sessiondataMo.remove(KEY_SIGNATURE_KEY));
        final byte[] sessiondata = cryptoContext.encrypt(encoder.encodeObject(sessiondataMo, ENCODER_FORMAT), encoder, ENCODER_FORMAT);
        tokendataMo.put(KEY_SESSIONDATA, sessiondata);
        
        // The tokendata must be signed otherwise the session data will not be
        // processed.
        final byte[] modifiedTokendata = encoder.encodeObject(tokendataMo, ENCODER_FORMAT);
        final byte[] signature = cryptoContext.sign(modifiedTokendata, encoder, ENCODER_FORMAT);
        mo.put(KEY_TOKENDATA, modifiedTokendata);
        mo.put(KEY_SIGNATURE, signature);
        
        // Confirm signature key.
        final MasterToken moMasterToken = new MasterToken(ctx, mo);
        final SecretKey moSignatureKey = moMasterToken.getSignatureKey();
        assertArrayEquals(masterToken.getSignatureKey().getEncoded(), moSignatureKey.getEncoded());
    }
    
    @Test
    public void missingSignatureAlgorithm() throws MslEncodingException, MslCryptoException, MslException, MslEncoderException {
        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final byte[] encode = masterToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        final ICryptoContext cryptoContext = ctx.getMslCryptoContext();
        
        // Before modifying the session data we need to decrypt it.
        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);
        final byte[] ciphertext = tokendataMo.getBytes(KEY_SESSIONDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject sessiondataMo = encoder.parseObject(plaintext);
        
        // After modifying the session data we need to encrypt it.
        assertNotNull(sessiondataMo.remove(KEY_SIGNATURE_ALGORITHM));
        final byte[] sessiondata = cryptoContext.encrypt(encoder.encodeObject(sessiondataMo, ENCODER_FORMAT), encoder, ENCODER_FORMAT);
        tokendataMo.put(KEY_SESSIONDATA, sessiondata);
        
        // The tokendata must be signed otherwise the session data will not be
        // processed.
        final byte[] modifiedTokendata = encoder.encodeObject(tokendataMo, ENCODER_FORMAT);
        final byte[] signature = cryptoContext.sign(modifiedTokendata, encoder, ENCODER_FORMAT);
        mo.put(KEY_TOKENDATA, modifiedTokendata);
        mo.put(KEY_SIGNATURE, signature);
        
        // Confirm default algorithm.
        final MasterToken moMasterToken = new MasterToken(ctx, mo);
        final SecretKey moSignatureKey = moMasterToken.getSignatureKey();
        assertEquals(JcaAlgorithm.HMAC_SHA256, moSignatureKey.getAlgorithm());
    }
    
    @Test
    public void invalidSignatureAlgorithm() throws MslEncodingException, MslCryptoException, MslException, MslEncoderException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.UNIDENTIFIED_ALGORITHM);
        
        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final byte[] encode = masterToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        final ICryptoContext cryptoContext = ctx.getMslCryptoContext();
        
        // Before modifying the session data we need to decrypt it.
        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);
        final byte[] ciphertext = tokendataMo.getBytes(KEY_SESSIONDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject sessiondataMo = encoder.parseObject(plaintext);
        
        // After modifying the session data we need to encrypt it.
        sessiondataMo.put(KEY_SIGNATURE_ALGORITHM, "x");
        final byte[] sessiondata = cryptoContext.encrypt(encoder.encodeObject(sessiondataMo, ENCODER_FORMAT), encoder, ENCODER_FORMAT);
        tokendataMo.put(KEY_SESSIONDATA, sessiondata);
        
        // The tokendata must be signed otherwise the session data will not be
        // processed.
        final byte[] modifiedTokendata = encoder.encodeObject(tokendataMo, ENCODER_FORMAT);
        final byte[] signature = cryptoContext.sign(modifiedTokendata, encoder, ENCODER_FORMAT);
        mo.put(KEY_TOKENDATA, modifiedTokendata);
        mo.put(KEY_SIGNATURE, signature);
        
        new MasterToken(ctx, mo);
    }
    
    @Test
    public void missingHmacAndSignatureKey() throws MslEncoderException, MslException, UnsupportedEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MASTERTOKEN_SESSIONDATA_PARSE_ERROR);

        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final byte[] encode = masterToken.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        
        final ICryptoContext cryptoContext = ctx.getMslCryptoContext();
        
        // Before modifying the session data we need to decrypt it.
        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);
        final byte[] ciphertext = tokendataMo.getBytes(KEY_SESSIONDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject sessiondataMo = encoder.parseObject(plaintext);
        
        // After modifying the session data we need to encrypt it.
        assertNotNull(sessiondataMo.remove(KEY_HMAC_KEY));
        assertNotNull(sessiondataMo.remove(KEY_SIGNATURE_KEY));
        final byte[] sessiondata = cryptoContext.encrypt(encoder.encodeObject(sessiondataMo, ENCODER_FORMAT), encoder, ENCODER_FORMAT);
        tokendataMo.put(KEY_SESSIONDATA, sessiondata);
        
        // The tokendata must be signed otherwise the session data will not be
        // processed.
        final byte[] modifiedTokendata = encoder.encodeObject(tokendataMo, ENCODER_FORMAT);
        final byte[] signature = cryptoContext.sign(modifiedTokendata, encoder, ENCODER_FORMAT);
        mo.put(KEY_TOKENDATA, modifiedTokendata);
        mo.put(KEY_SIGNATURE, signature);
        
        new MasterToken(ctx, mo);
    }
    
    @Test
    public void invalidHmacAndSignatureKey() throws MslEncoderException, MslException, UnsupportedEncodingException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.MASTERTOKEN_KEY_CREATION_ERROR);

        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final MslObject mo = MslTestUtils.toMslObject(encoder, masterToken);
        
        final ICryptoContext cryptoContext = ctx.getMslCryptoContext();
        
        // Before modifying the session data we need to decrypt it.
        final byte[] tokendata = mo.getBytes(KEY_TOKENDATA);
        final MslObject tokendataMo = encoder.parseObject(tokendata);
        final byte[] ciphertext = tokendataMo.getBytes(KEY_SESSIONDATA);
        final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
        final MslObject sessiondataMo = encoder.parseObject(plaintext);
        
        // After modifying the session data we need to encrypt it.
        sessiondataMo.put(KEY_HMAC_KEY, "");
        sessiondataMo.put(KEY_SIGNATURE_KEY, "");
        final byte[] sessiondata = cryptoContext.encrypt(encoder.encodeObject(sessiondataMo, ENCODER_FORMAT), encoder, ENCODER_FORMAT);
        tokendataMo.put(KEY_SESSIONDATA, sessiondata);
        
        // The tokendata must be signed otherwise the session data will not be
        // processed.
        final byte[] modifiedTokendata = encoder.encodeObject(tokendataMo, ENCODER_FORMAT);
        final byte[] signature = cryptoContext.sign(modifiedTokendata, encoder, ENCODER_FORMAT);
        mo.put(KEY_TOKENDATA, modifiedTokendata);
        mo.put(KEY_SIGNATURE, signature);
        
        new MasterToken(ctx, mo);
    }
    
    @Test
    public void isRenewable() throws MslEncodingException, MslCryptoException {
        final Date renewalWindow = new Date();
        final Date expiration = new Date(System.currentTimeMillis() + 1000);
        final MasterToken masterToken = new MasterToken(ctx, renewalWindow, expiration, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        
        final Date now = new Date();
        assertTrue(masterToken.isRenewable(null));
        assertTrue(masterToken.isRenewable(now));
        assertFalse(masterToken.isExpired(null));
        assertFalse(masterToken.isExpired(now));
        
        final Date before = new Date(renewalWindow.getTime() - 1000);
        assertFalse(masterToken.isRenewable(before));
        assertFalse(masterToken.isExpired(before));
        
        final Date after = new Date(expiration.getTime() + 1000);
        assertTrue(masterToken.isRenewable(after));
        assertTrue(masterToken.isExpired(after));
    }
    
    @Test
    public void isExpired() throws MslEncodingException, MslCryptoException {
        final Date renewalWindow = new Date(System.currentTimeMillis() - 1000);
        final Date expiration = new Date();
        final MasterToken masterToken = new MasterToken(ctx, renewalWindow, expiration, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        
        final Date now = new Date();
        assertTrue(masterToken.isRenewable(null));
        assertTrue(masterToken.isRenewable(now));
        assertTrue(masterToken.isExpired(null));
        assertTrue(masterToken.isExpired(now));
        
        final Date before = new Date(renewalWindow.getTime() - 1000);
        assertFalse(masterToken.isRenewable(before));
        assertFalse(masterToken.isExpired(before));
        
        final Date after = new Date(expiration.getTime() + 1000);
        assertTrue(masterToken.isRenewable(after));
        assertTrue(masterToken.isExpired(after));
    }
    
    @Test
    public void notRenewableOrExpired() throws MslEncodingException, MslCryptoException {
        final Date renewalWindow = new Date(System.currentTimeMillis() + 1000);
        final Date expiration = new Date(System.currentTimeMillis() + 2000);
        final MasterToken masterToken = new MasterToken(ctx, renewalWindow, expiration, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        
        final Date now = new Date();
        assertFalse(masterToken.isRenewable(null));
        assertFalse(masterToken.isRenewable(now));
        assertFalse(masterToken.isExpired(null));
        assertFalse(masterToken.isExpired(now));
        
        final Date before = new Date(renewalWindow.getTime() - 1000);
        assertFalse(masterToken.isRenewable(before));
        assertFalse(masterToken.isExpired(before));
        
        final Date after = new Date(expiration.getTime() + 1000);
        assertTrue(masterToken.isRenewable(after));
        assertTrue(masterToken.isExpired(after));
    }
    
    @Test
    public void isNewerThanSequenceNumbers() throws MslEncodingException, MslCryptoException {
        final long sequenceNumberA = 1;
        final long sequenceNumberB = 2;
        final MasterToken masterTokenA = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, sequenceNumberA, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final MasterToken masterTokenB = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, sequenceNumberB, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        
        assertTrue(masterTokenB.isNewerThan(masterTokenA));
        assertFalse(masterTokenA.isNewerThan(masterTokenB));
        assertFalse(masterTokenA.isNewerThan(masterTokenA));
    }
    
    @Test
    public void isNewerThanSequenceNumbersWrapAround() throws MslEncodingException, MslCryptoException {
        // Anything within 128 is newer.
        for (long seqNo = MslConstants.MAX_LONG_VALUE - 127; seqNo <= MslConstants.MAX_LONG_VALUE && seqNo != 0; seqNo = incrementSequenceNumber(seqNo, 1)) {
            final long minus1 = decrementSequenceNumber(seqNo, 1);
            final long plus1 = incrementSequenceNumber(seqNo, 1);
            final long plus127 = incrementSequenceNumber(seqNo, 127); 
            final long plus128 = incrementSequenceNumber(seqNo, 128);

            final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, seqNo, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
            final MasterToken minus1MasterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, minus1, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
            final MasterToken plus1MasterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, plus1, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
            final MasterToken plus127MasterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, plus127, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
            final MasterToken plus128MasterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, plus128, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);

            assertFalse("seqNo = " + seqNo, minus1MasterToken.isNewerThan(masterToken));
            assertTrue("seqNo = " + seqNo, masterToken.isNewerThan(minus1MasterToken));
            assertTrue("seqNo = " + seqNo, plus1MasterToken.isNewerThan(masterToken));
            assertFalse("seqNo = " + seqNo, masterToken.isNewerThan(plus1MasterToken));
            assertTrue("seqNo = " + seqNo, plus127MasterToken.isNewerThan(masterToken));
            assertFalse("seqNo = " + seqNo, masterToken.isNewerThan(plus127MasterToken));
            assertFalse("seqNo = " + seqNo, plus128MasterToken.isNewerThan(masterToken));
            assertTrue("seqNo = " + seqNo, masterToken.isNewerThan(plus128MasterToken));
        }
    }
    
    @Test
    public void isNewerThanExpiration() throws MslEncodingException, MslCryptoException {
        final Date expirationA = new Date(EXPIRATION.getTime());
        final Date expirationB = new Date(EXPIRATION.getTime() + 10000);
        final MasterToken masterTokenA = new MasterToken(ctx, RENEWAL_WINDOW, expirationA, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final MasterToken masterTokenB = new MasterToken(ctx, RENEWAL_WINDOW, expirationB, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        
        assertTrue(masterTokenB.isNewerThan(masterTokenA));
        assertFalse(masterTokenA.isNewerThan(masterTokenB));
        assertFalse(masterTokenA.isNewerThan(masterTokenA));
    }
    
    @Test
    public void isNewerSerialNumber() throws MslEncodingException, MslCryptoException {
        final long serialNumberA = 1;
        final long serialNumberB = 2;
        final long sequenceNumberA = 1;
        final long sequenceNumberB = 2;
        final MasterToken masterTokenA = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, sequenceNumberA, serialNumberA, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final MasterToken masterTokenB = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, sequenceNumberB, serialNumberB, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        
        assertTrue(masterTokenB.isNewerThan(masterTokenA));
        assertFalse(masterTokenA.isNewerThan(masterTokenB));
    }
    
    @Test
    public void equalsTrustedUntrusted() throws MslException, MslEncoderException {
        final Date renewalWindow = new Date(System.currentTimeMillis() + 1000);
        final Date expiration = new Date(System.currentTimeMillis() + 2000);
        final String identity = MockPresharedAuthenticationFactory.PSK_ESN;
        final SecretKey encryptionKey = MockPresharedAuthenticationFactory.KPE;
        final SecretKey hmacKey = MockPresharedAuthenticationFactory.KPH;
        final MasterToken masterToken = new MasterToken(ctx, renewalWindow, expiration, 1L, 1L, null, identity, encryptionKey, hmacKey);
        
        final MslObject mo = MslTestUtils.toMslObject(encoder, masterToken);
        final byte[] signature = mo.getBytes("signature");
        ++signature[1];
        mo.put("signature", signature);
        final MasterToken untrustedMasterToken = new MasterToken(ctx, mo);
        
        assertTrue(masterToken.equals(untrustedMasterToken));
        assertEquals(masterToken.hashCode(), untrustedMasterToken.hashCode());
    }
    
    @Test
    public void equalsSerialNumber() throws MslException, MslEncoderException {
        final long serialNumberA = 1;
        final long serialNumberB = 2;
        final MasterToken masterTokenA = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, serialNumberA, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final MasterToken masterTokenB = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, serialNumberB, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final MasterToken masterTokenA2 = new MasterToken(ctx, MslTestUtils.toMslObject(encoder, masterTokenA));
        
        assertTrue(masterTokenA.equals(masterTokenA));
        assertEquals(masterTokenA.hashCode(), masterTokenA.hashCode());
        
        assertFalse(masterTokenA.equals(masterTokenB));
        assertFalse(masterTokenB.equals(masterTokenA));
        assertTrue(masterTokenA.hashCode() != masterTokenB.hashCode());
        
        assertTrue(masterTokenA.equals(masterTokenA2));
        assertTrue(masterTokenA2.equals(masterTokenA));
        assertEquals(masterTokenA.hashCode(), masterTokenA2.hashCode());
    }
    
    @Test
    public void equalsSequenceNumber() throws MslEncodingException, MslCryptoException, MslException, MslEncoderException {
        final long sequenceNumberA = 1;
        final long sequenceNumberB = 2;
        final MasterToken masterTokenA = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, sequenceNumberA, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final MasterToken masterTokenB = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, sequenceNumberB, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final MasterToken masterTokenA2 = new MasterToken(ctx, MslTestUtils.toMslObject(encoder, masterTokenA));
        
        assertTrue(masterTokenA.equals(masterTokenA));
        assertEquals(masterTokenA.hashCode(), masterTokenA.hashCode());
        
        assertFalse(masterTokenA.equals(masterTokenB));
        assertFalse(masterTokenB.equals(masterTokenA));
        assertTrue(masterTokenA.hashCode() != masterTokenB.hashCode());
        
        assertTrue(masterTokenA.equals(masterTokenA2));
        assertTrue(masterTokenA2.equals(masterTokenA));
        assertEquals(masterTokenA.hashCode(), masterTokenA2.hashCode());
    }
    
    @Test
    public void equalsExpiration() throws MslEncodingException, MslCryptoException, MslException, MslEncoderException {
        final Date expirationA = new Date(EXPIRATION.getTime());
        final Date expirationB = new Date(EXPIRATION.getTime() + 10000);
        final MasterToken masterTokenA = new MasterToken(ctx, RENEWAL_WINDOW, expirationA, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final MasterToken masterTokenB = new MasterToken(ctx, RENEWAL_WINDOW, expirationB, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        final MasterToken masterTokenA2 = new MasterToken(ctx, MslTestUtils.toMslObject(encoder, masterTokenA));
        
        assertTrue(masterTokenA.equals(masterTokenA));
        assertEquals(masterTokenA.hashCode(), masterTokenA.hashCode());
        
        assertFalse(masterTokenA.equals(masterTokenB));
        assertFalse(masterTokenB.equals(masterTokenA));
        assertTrue(masterTokenA.hashCode() != masterTokenB.hashCode());
        
        assertTrue(masterTokenA.equals(masterTokenA2));
        assertTrue(masterTokenA2.equals(masterTokenA));
        assertEquals(masterTokenA.hashCode(), masterTokenA2.hashCode());
    }
    
    @Test
    public void equalsObject() throws MslEncodingException, MslCryptoException {
        final MasterToken masterToken = new MasterToken(ctx, RENEWAL_WINDOW, EXPIRATION, SEQUENCE_NUMBER, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, SIGNATURE_KEY);
        assertFalse(masterToken.equals(null));
        assertFalse(masterToken.equals(IDENTITY));
        assertTrue(masterToken.hashCode() != IDENTITY.hashCode());
    }
    
    /** MSL context. */
    private static MslContext ctx;
    /** MSL encoder factory. */
    private static MslEncoderFactory encoder;
}
