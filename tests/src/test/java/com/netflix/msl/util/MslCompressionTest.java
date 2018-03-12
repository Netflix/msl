/**
 * Copyright (c) 2018 Netflix, Inc.  All rights reserved.
 */
package com.netflix.msl.util;

import static org.junit.Assert.assertArrayEquals;

import org.junit.Rule;
import org.junit.Test;

import com.netflix.msl.MslConstants.CompressionAlgorithm;
import com.netflix.msl.MslError;
import com.netflix.msl.MslException;
import com.netflix.msl.test.ExpectedMslException;

/**
 * <p>MSL compression unit tests.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MslCompressionTest {
    @Rule
    public ExpectedMslException thrown = ExpectedMslException.none();

    @Test
    public void compressRatioExceeded() throws MslException {
        final byte[] codes = new byte[] {
            (byte)0x00, (byte)0x80, (byte)0x40, (byte)0x60, (byte)0x50, (byte)0x38, (byte)0x24, (byte)0x16, (byte)0x0d, (byte)0x07, (byte)0x84, (byte)0x42, (byte)0x61, (byte)0x50, (byte)0xb8, (byte)0x64,
            (byte)0x36, (byte)0x1d, (byte)0x0f, (byte)0x88, (byte)0x44, (byte)0x62, (byte)0x51, (byte)0x38, (byte)0xa4, (byte)0x56, (byte)0x2d, (byte)0x17, (byte)0x8c, (byte)0x46, (byte)0x63, (byte)0x51,
            (byte)0xb8, (byte)0xe4, (byte)0x76, (byte)0x3d, (byte)0x1f, (byte)0x90, (byte)0x48, (byte)0x64, (byte)0x52, (byte)0x39, (byte)0x24, (byte)0x96, (byte)0x4d, (byte)0x27, (byte)0x94, (byte)0x4a,
            (byte)0x65, (byte)0x52, (byte)0x00 };
        final byte[] data = new byte[1024];

        final byte[] compressed = MslCompression.compress(CompressionAlgorithm.LZW, data);
        assertArrayEquals(codes, compressed);

        final byte[] uncompressed = MslCompression.uncompress(CompressionAlgorithm.LZW, codes);
        assertArrayEquals(data, uncompressed);

        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.UNCOMPRESSION_ERROR);
        MslCompression.setMaxDeflateRatio(10);
        MslCompression.uncompress(CompressionAlgorithm.LZW, codes);
    }
}
