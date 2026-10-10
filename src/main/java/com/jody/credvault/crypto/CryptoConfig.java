package com.jody.credvault.crypto;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** Makes CryptoService available to the rest of the app as a Spring bean. */
@Configuration
public class CryptoConfig {

    @Bean
    public CryptoService cryptoService(
            @Value("${credvault.crypto.iterations:600000}") int iterations) {
        return new CryptoService(iterations);
    }
}
