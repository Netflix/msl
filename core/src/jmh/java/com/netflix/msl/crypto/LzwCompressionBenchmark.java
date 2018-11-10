package com.netflix.msl.crypto;

import com.netflix.msl.MslConstants;
import com.netflix.msl.MslException;
import com.netflix.msl.util.MslCompression;
import org.apache.commons.io.IOUtils;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.profile.GCProfiler;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import java.io.IOException;
import java.io.InputStream;

@State(Scope.Thread)
public class LzwCompressionBenchmark {
    private byte[] license;
    private byte[] licenseCompressed;

    @Setup
    public void prepare() throws IOException, MslException {
        InputStream inputStream = getClass().getResourceAsStream("/LICENSE.txt");
        license  = IOUtils.toByteArray(inputStream);
        licenseCompressed = MslCompression.compress(MslConstants.CompressionAlgorithm.LZW, license);
    }

    @Benchmark
    public byte[] measureCompressThroughput() throws MslException {
        return MslCompression.compress(MslConstants.CompressionAlgorithm.LZW, license);
    }

    @Benchmark
    public byte[] measureUncompressThroughput() throws MslException {
        return MslCompression.uncompress(MslConstants.CompressionAlgorithm.LZW, licenseCompressed);
    }

    public static void main(String[] args) throws RunnerException {
        Options opt = new OptionsBuilder()
                .include(".*" + LzwCompressionBenchmark.class.getSimpleName() + ".*")
                .warmupIterations(5)
                .measurementIterations(5)
                .forks(4)
                .addProfiler( GCProfiler.class )
                .build();

        new Runner(opt).run();
    }
}
