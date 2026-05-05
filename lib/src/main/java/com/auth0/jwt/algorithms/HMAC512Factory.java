package com.auth0.jwt.algorithms;

import java.util.function.Supplier;

public class HMAC512Factory implements AlgorithmFactory {
    private final Supplier<Algorithm> supplier;

    public HMAC512Factory(String secret) {
        this.supplier = () -> new HMACAlgorithm("HS512", "HmacSHA512", secret);
    }

    public HMAC512Factory(byte[] secret) {
        this.supplier = () -> new HMACAlgorithm("HS512", "HmacSHA512", secret);
    }

    @Override
    public Algorithm create() {
        return supplier.get();
    }
}