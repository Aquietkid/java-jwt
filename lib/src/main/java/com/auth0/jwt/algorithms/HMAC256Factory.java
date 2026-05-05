package com.auth0.jwt.algorithms;

import java.util.function.Supplier;

public class HMAC256Factory implements AlgorithmFactory {
    private final Supplier<Algorithm> supplier;

    public HMAC256Factory(String secret) {
        this.supplier = () -> new HMACAlgorithm("HS256", "HmacSHA256", secret);
    }

    public HMAC256Factory(byte[] secret) {
        this.supplier = () -> new HMACAlgorithm("HS256", "HmacSHA256", secret);
    }

    @Override
    public Algorithm create() {
        return supplier.get();
    }
}