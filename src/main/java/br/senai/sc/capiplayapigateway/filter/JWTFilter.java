package br.senai.sc.capiplayapigateway.filter;

import br.senai.sc.capiplayapigateway.utils.TokenService;
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
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

    private final List<Rota> autorizadas = new ArrayList<>();
    private final List<Rota> indefinidas = new ArrayList<>();

    private record Rota(String path, HttpMethod method) {
        boolean match(String path, HttpMethod method) {
            return this.method.equals(method) && new AntPathMatcher().match(this.path, path);
        }
    }

    public JWTFilter() {
        indefinidas.add(new Rota("/api/usuario/login", HttpMethod.POST));
        indefinidas.add(new Rota("/api/usuario/cadastro", HttpMethod.POST));
        indefinidas.add(new Rota("/api/video/buscar-completo/**", HttpMethod.GET));
        indefinidas.add(new Rota("/api/usuario/static/**", HttpMethod.GET));
        indefinidas.add(new Rota("/api/video/static/**", HttpMethod.GET));
        indefinidas.add(new Rota("/api/video/buscar-reels", HttpMethod.GET));
        indefinidas.add(new Rota("/api/usuario/anonimo", HttpMethod.POST));
        indefinidas.add(new Rota("/api/video/buscar-resumido", HttpMethod.GET));

        autorizadas.add(new Rota("/api/usuario", HttpMethod.GET));
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request =  exchange.getRequest();
        ServerHttpResponse response = exchange.getResponse();

        String requestPath = request.getPath().toString();
        HttpMethod requestMethod = request.getMethod();

        boolean isIndefinida = indefinidas.stream()
                .anyMatch(rota -> rota.match(requestPath, requestMethod));

        if (isIndefinida) {
            return chain.filter(exchange);
        }

        var authHeader = request.getHeaders().getFirst("Authorization");

        if (authHeader == null) {
            response.setStatusCode(HttpStatus.UNAUTHORIZED);
            return response.setComplete();
        }
        String token = authHeader.replace("Bearer ", "");

        if (!tokenService.validToken(token)) {
            response.setStatusCode(HttpStatus.UNAUTHORIZED);
            return response.setComplete();
        }

        DecodedJWT decodedJWT = JWT.decode(token);
        boolean anonimo = decodedJWT.getClaim("anonimo").asBoolean();

        boolean autorizado = autorizadas.stream()
                .anyMatch(rota -> rota.match(requestPath, requestMethod)); ;

        if (anonimo && autorizado) {
            response.setStatusCode(HttpStatus.UNAUTHORIZED);
            return response.setComplete();
        }
        ServerHttpRequest newRequest = request.mutate()
                .header("usuarioId", tokenService.getId(token))
                .build();

        return chain.filter(exchange.mutate().request(newRequest).build());
    }

    @Override
    public int getOrder() {
        return 0;
    }
}
