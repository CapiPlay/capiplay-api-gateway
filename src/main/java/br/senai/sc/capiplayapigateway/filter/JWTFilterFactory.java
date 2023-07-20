package br.senai.sc.capiplayapigateway.filter;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.stereotype.Component;

@Component
public class JWTFilterFactory extends AbstractGatewayFilterFactory<JWTFilterFactory.Config> {

    public JWTFilterFactory() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return new JWTFilter();
    }

    public static class Config {
    }
}