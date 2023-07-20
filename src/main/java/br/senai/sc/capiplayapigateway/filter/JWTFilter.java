package br.senai.sc.capiplayapigateway.filter;

import br.senai.sc.capiplayapigateway.utils.TokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Component
@Order(0)
public class JWTFilter implements GatewayFilter, Ordered {


    private final TokenService tokenService = new TokenService();

    private final List<String> rotasPublicas = new ArrayList<>();


    public JWTFilter() {
        rotasPublicas.add("/api/usuario/login");
        rotasPublicas.add("/api/usuario/cadastro");
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request =  exchange.getRequest();
        ServerHttpResponse response = exchange.getResponse();

        if (rotasPublicas.contains(request.getPath().toString())){
            return chain.filter(exchange);
        }

        var authHeader = request.getHeaders().getFirst("Authorization");
        if (authHeader == null) {
            response.setStatusCode(HttpStatus.UNAUTHORIZED);
            return response.setComplete();
        }
        String token = authHeader.replace("Bearer ", "");
        if (tokenService.validToken(token)) {
            return chain.filter(exchange);
        }
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        return response.setComplete();
    }

    @Override
    public int getOrder() {
        return 0;
    }
}
