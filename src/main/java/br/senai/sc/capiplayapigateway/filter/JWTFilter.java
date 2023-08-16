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
        // ROTAS PÚBLICAS (SEM TOKEN)
        //Usuario
        indefinidas.add(new Rota("/api/usuario/login", HttpMethod.POST));
        indefinidas.add(new Rota("/api/usuario/cadastro", HttpMethod.POST));
        indefinidas.add(new Rota("/api/usuario/static/**", HttpMethod.GET));
        indefinidas.add(new Rota("/api/video/static/**", HttpMethod.GET));
        indefinidas.add(new Rota("/api/usuario/anonimo", HttpMethod.POST));
        indefinidas.add(new Rota("/api/video/buscar-videos-canal", HttpMethod.GET));

        // ROTAS QUE PRECISAM DE TOKEN (ANONIMO OU NAO)
        //Usuario
        autorizadas.add(new Rota("/api/usuario", HttpMethod.GET));
        //Video
        autorizadas.add(new Rota("/api/video/criar", HttpMethod.POST));
        //Engajamento
        autorizadas.add(new Rota("/api/engajamento/comentario/buscar-quantidade-respostas", HttpMethod.GET));
        autorizadas.add(new Rota("/api/engajamento/comentario/buscar-todos-por-data", HttpMethod.GET));
        autorizadas.add(new Rota("/api/engajamento/comentario/buscar-todos-por-video", HttpMethod.GET));
        autorizadas.add(new Rota("/api/engajamento/comentario", HttpMethod.POST));
        autorizadas.add(new Rota("/api/engajamento/comentario", HttpMethod.GET));
        autorizadas.add(new Rota("/api/engajamento/comentario", HttpMethod.DELETE));
        autorizadas.add(new Rota("/api/engajamento/reacaoResposta", HttpMethod.POST));
        autorizadas.add(new Rota("/api/engajamento/reacaoResposta", HttpMethod.POST));
        autorizadas.add(new Rota("/api/engajamento/reacaoResposta", HttpMethod.POST));
        autorizadas.add(new Rota("/api/engajamento/reacaoResposta/buscar-todos-por-resposta", HttpMethod.POST));
        autorizadas.add(new Rota("/api/engajamento/reacaoComentario", HttpMethod.POST));
        autorizadas.add(new Rota("/api/engajamento/reacaoComentario", HttpMethod.POST));
        autorizadas.add(new Rota("/api/engajamento/reacaoComentario/buscar-todos-por-comentario", HttpMethod.POST));
        autorizadas.add(new Rota("/api/engajamento/reacao", HttpMethod.POST));
        autorizadas.add(new Rota("/api/engajamento/reacao", HttpMethod.POST));
        autorizadas.add(new Rota("/api/engajamento/reacao/buscar-todos-por-video", HttpMethod.POST));
        autorizadas.add(new Rota("/api/engajamento/resposta", HttpMethod.POST));
        autorizadas.add(new Rota("/api/engajamento/resposta", HttpMethod.POST));
        autorizadas.add(new Rota("/api/engajamento/resposta", HttpMethod.POST));
        autorizadas.add(new Rota("/api/engajamento/resposta/buscar-todos-por-comentario", HttpMethod.GET));
        autorizadas.add(new Rota("/api/engajamento/historico", HttpMethod.POST));
        autorizadas.add(new Rota("/api/engajamento/historico", HttpMethod.POST));
        autorizadas.add(new Rota("/api/engajamento/historico/buscar-todos-históricos-por-data", HttpMethod.POST));
        autorizadas.add(new Rota("/api/engajamento/historico/buscar-todos-históricos-por-usuario", HttpMethod.POST));
        autorizadas.add(new Rota("/api/engajamento/inscricao", HttpMethod.POST));
        autorizadas.add(new Rota("/api/engajamento/inscricao", HttpMethod.POST));
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
