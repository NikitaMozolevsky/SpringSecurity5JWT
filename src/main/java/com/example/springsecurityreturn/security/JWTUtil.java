package com.example.springsecurityreturn.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.ZonedDateTime;
import java.util.Date;

//Будет генерировать JWT и отправлять
//Валидировать получениый от пользователя JWT
@Component
public class JWTUtil {

    //получение secret из application.properties
    @Value("${jwt_secret}")
    private String secret;

    public String generateToken(String username) { //герерация токена по username
        //срок годности 60 минут с текущего момента в текущей зоне времени
        Date expirationDate = Date.from(ZonedDateTime.now().plusMinutes(60).toInstant());

        //конструирование JWT
        return JWT.create()
                //информация о том, что здесь хранится
                .withSubject("User details")
                //данные в паре key - value
                .withClaim("username", username)
                //Время выдачи токена
                .withIssuedAt(new Date())
                //кто выдал токен
                .withIssuer("Nikitos (APP NAME)")
                //когда иссякнет срок годности
                .withExpiresAt(expirationDate)
                //передается ключ JWT, хранящийся только на нашем сервере
                .sign(Algorithm.HMAC256(secret));
    }

    //валидация и извлечение имени пользователя
    //выбрасывается JWTVerificationException если токен не пошел верификацию
    public String validateTokenAndRetrieveClaim(String token) throws JWTVerificationException {
        //валидатор
        JWTVerifier verifier = JWT.require(Algorithm.HMAC256(secret))
                .withSubject("User details")
                .withIssuer("Nikitos (APP NAME)")
                .build();
        //валидация и получение раскодированного токена
        DecodedJWT decodedJWT = verifier.verify(token);
        return decodedJWT.getClaim("username").asString();
    }
}
