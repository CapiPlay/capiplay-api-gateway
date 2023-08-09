package br.senai.sc.capiplayapigateway.filter;

import br.senai.sc.capiplayapigateway.utils.TokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpRequest;
import org.springframework.http.HttpStatus;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.lang.reflect.Array;
import java.util.*;
import java.util.regex.Pattern;

@Component
@Order(0)
public class JWTFilter implements GatewayFilter, Ordered {

    private final TokenService tokenService = new TokenService();

    private final HashMap<String, HttpMethod> rotasPublicas = new HashMap<>();
    private final AntPathMatcher pathMatcher = new AntPathMatcher();



    public JWTFilter() {
        rotasPublicas.put("/api/usuario/login", HttpMethod.POST);
        rotasPublicas.put("/api/usuario/cadastro", HttpMethod.POST);
        rotasPublicas.put("/api/video/buscar-completo/**", HttpMethod.GET);
        rotasPublicas.put("/api/usuario/static/**", HttpMethod.GET);
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request =  exchange.getRequest();
        ServerHttpResponse response = exchange.getResponse();

        String requestPath = request.getPath().toString();
        HttpMethod requestMethod = request.getMethod();

        boolean isPublicRoute = rotasPublicas.entrySet().stream()
                .anyMatch(entry -> pathMatcher.match(entry.getKey(), requestPath) &&
                        entry.getValue().equals(requestMethod));


        System.out.println(isPublicRoute);


        if (isPublicRoute) {
            return chain.filter(exchange);
        }
      

        var authHeader = request.getHeaders().getFirst("Authorization");
        if (authHeader == null) {
            response.setStatusCode(HttpStatus.UNAUTHORIZED);
            return response.setComplete();
        }
        String token = authHeader.replace("Bearer ", "");
        if (tokenService.validToken(token)) {
            ServerHttpRequest newRequest = request.mutate()
                    .header("usuarioId", tokenService.getId(token))
                    .build();

            return chain.filter(exchange.mutate().request(newRequest).build());
        }
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        return response.setComplete();
    }

    @Override
    public int getOrder() {
        return 0;
    }
}
