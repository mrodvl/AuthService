package org.example.authservice.service;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * Сервис для работы с JWT-токенами, предоставляющий методы для генерации, валидации и извлечения данных из токенов.
 */
@Service
public class JwtService {
    private String secretKeyStr = "JlkjubhlIBLjgljyvGJvk43223UGVUKVKJ";
    private long jwtExpression = 60000 * 200;
    private long refreshExpression = 60000 * 500;



    /**
     * Извлекает имя пользователя из токена JWT.
     *
     * @param token токен JWT
     * @return имя пользователя, извлеченное из токена
     */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Извлекает указанное утверждение (claim) из токена JWT.
     *
     * @param token токен JWT
     * @param claimsResolver функция для извлечения конкретного утверждения из объекта Claims
     * @param <T> тип возвращаемого утверждения
     * @return значение утверждения, извлеченное из токена
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }


    //# 1 вспомогательный метод 2
    private Claims extractAllClaims(String token) {
        SecretKey secretKey = Keys.hmacShaKeyFor(secretKeyStr.getBytes(StandardCharsets.UTF_8));
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /**
     * Генерирует JWT-токен с дополнительными утверждениями.
     *
     * @param extraClaims  дополнительные утверждения для включения в токен
     * @param userDetails  данные пользователя для генерации токена
     * @return строка, представляющая JWT-токен
     */
    public String generateToken(Map<String,Object> extraClaims,UserDetails userDetails){
        return buildToken(extraClaims,userDetails,jwtExpression);
    }
    //#2 генерация токена без Claims
    public String generateToken(UserDetails userDetails){
        return buildToken(new HashMap<>(),userDetails,jwtExpression);
    }


    /**
     * Генерирует токен обновления (refresh token) для пользователя.
     *
     * @param userDetails данные пользователя для генерации токена
     * @return строка, представляющая токен обновления
     */
    public String generateRefreshToken(UserDetails userDetails){
        return buildToken(new HashMap<>(),userDetails,refreshExpression);
    }

    /**
     * Создает JWT-токен с указанными утверждениями, данными пользователя и сроком действия.
     *
     * @param extraClaims  дополнительные утверждения для включения в токен
     * @param userDetails  данные пользователя
     * @param expiration   срок действия токена в миллисекундах
     * @return строка, представляющая JWT-токен
     */
    private String buildToken(Map<String, Object> extraClaims, UserDetails userDetails, Long expiration) {
        SecretKey secretKey = Keys.hmacShaKeyFor(secretKeyStr.getBytes(StandardCharsets.UTF_8));

        return Jwts.builder()
                .claims(extraClaims)
                .subject(userDetails.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(secretKey, SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * Проверяет, истек ли срок действия токена.
     *
     * @param token токен JWT
     * @return true, Sen, если срок действия токена истек, иначе false
     */
    public boolean isTokenExpired(String token){
        Date date = extractClaim(token, Claims::getExpiration);
        return date.before(new Date());
    }

    /**
     * Проверяет токен JWT на соответствие данным пользователя.
     *
     * @param token токен JWT для проверки
     * @param userDetails данные пользователя для проверки
     * @return true, если токен действителен, false в противном случае
     */
    public boolean isValidToken(String token, UserDetails userDetails){
        String userNameFromToken = extractUsername(token);
        return userNameFromToken.equals(userDetails.getUsername()) && !isTokenExpired(token);

    }
}
