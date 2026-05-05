package com.auth0.jwt.algorithms;

import com.auth0.jwt.interfaces.KeyProvider;

public interface AlgorithmFactory {

    public Algorithm create();
}
