package br.senai.sc.capiplayapigateway.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

import static com.auth0.jwt.algorithms.Algorithm.HMAC256;

@Service
public class TokenService {

    public Boolean validToken(String token){
        try {
            JWT.require(HMAC256("capiplay"))
                    .withIssuer("capiplay")
                    .build()
                    .verify(token);
            return true;
        } catch (JWTVerificationException a) {
            a.printStackTrace();
            return false;
        }
    }

    public String getId(String token) {
        return JWT.decode(token).getClaims().get("usuarioId").toString();
    }


    private Instant genExpirationDate(){
        return LocalDateTime.now().plusHours(2).toInstant(ZoneOffset.of("-03:00"));
    }
}
