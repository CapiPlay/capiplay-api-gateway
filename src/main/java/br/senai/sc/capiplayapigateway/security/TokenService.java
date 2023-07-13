package br.senai.sc.capiplayapigateway.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.JWTVerificationException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

import static com.auth0.jwt.algorithms.Algorithm.HMAC256;

@Service
public class TokenService {

    @Value("${secret.key}")
    private String secret;

    public String validToken(String token){
        try {
            return JWT.require(HMAC256(secret))
                    .withIssuer("capiplay")
                    .build()
                    .verify(token)
                    .getSubject();
        } catch (JWTVerificationException a) {
            return "";
        }
    }


    private Instant genExpirationDate(){
        return LocalDateTime.now().plusHours(2).toInstant(ZoneOffset.of("-03:00"));
    }
}
