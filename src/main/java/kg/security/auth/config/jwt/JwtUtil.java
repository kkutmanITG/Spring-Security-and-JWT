package kg.security.auth.config.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;

/**
 * JwtUtil – Генерация и валидация JWT
 * Это утилитный класс, который отвечает за:
 * Создание (генерацию) JWT-токена.
 * Проверку валидности токена (не истёк ли, не поддельный ли).
 * Извлечение данных из токена (например, email пользователя).
 */

@Slf4j
@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secretKey;

    @Value("${jwt.expiration}")
    private long expirationTime;

    private SecretKey getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    // Генерация токена
    public String generateToken(String username) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expirationTime);

        return Jwts.builder()
                .subject(username)
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(getSignInKey())
                .compact();
    }

    // Валидация токена
    public boolean validateToken(String token, String expectedUsername) {
        try {
            String username = getUsernameFromToken(token);
            return username.equals(expectedUsername) && !isTokenExpired(token);
        } catch (ExpiredJwtException e) {
            log.warn("JWT token expired: {}", e.getMessage());
        } catch (JwtException e) {
            log.warn("Invalid JWT token: {}", e.getMessage());
        } catch (Exception e) {
            log.error("Unexpected error during token validation", e);
        }
        return false;
    }

    // Получение имени пользователя
    public String getUsernameFromToken(String token) {
        return parseClaims(token).getPayload().getSubject();
    }

    // Получение даты истечения
    public Date getExpirationDateFromToken(String token) {
        return parseClaims(token).getPayload().getExpiration();
    }

    // Проверка на истечение
    private boolean isTokenExpired(String token) {
        Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }

    // Разбор токена
    private Jws<Claims> parseClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSignInKey())
                .build()
                .parseSignedClaims(token);
    }
}