package com.auth0.jwt.algorithms;

import java.util.function.Supplier;

public class HMAC384Factory implements AlgorithmFactory {
    private final Supplier<Algorithm> supplier;

    public HMAC384Factory(String secret) {
        this.supplier = () -> new HMACAlgorithm("HS384", "HmacSHA384", secret);
    }

    public HMAC384Factory(byte[] secret) {
        this.supplier = () -> new HMACAlgorithm("HS384", "HmacSHA384", secret);
    }

    @Override
    public Algorithm create() {
        return supplier.get();
    }
}