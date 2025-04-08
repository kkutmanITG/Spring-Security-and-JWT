package kg.security.auth.config.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.ExpiredJwtException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secretKey;

    private final long expirationTime = 1000 * 60 * 60;  // 1 час

    // Генерация токена
    public String generateToken(String username) {
        return Jwts.builder()
                .setSubject(username)  // Субъект - это имя пользователя
                .setIssuedAt(new Date())  // Время создания токена
                .setExpiration(new Date(System.currentTimeMillis() + expirationTime))  // Время истечения токена
                .signWith(SignatureAlgorithm.HS256, secretKey)  // Подписываем токен с использованием секретного ключа
                .compact();  // Генерируем токен
    }

    // Валидация токена
    public boolean validateToken(String token, String username) {
        try {
            String tokenUsername = getUsernameFromToken(token);
            return (username.equals(tokenUsername)) && !isTokenExpired(token);
        } catch (ExpiredJwtException e) {
            System.out.println("Токен истек: " + e.getMessage());
        } catch (JwtException e) {
            System.out.println("Ошибка JWT: " + e.getMessage());
        }
        return false;
    }

    // Получение имени пользователя из токена
    public String getUsernameFromToken(String token) {
        Jws<Claims> claimsJws = Jwts.parser()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token);
        return claimsJws.getBody().getSubject();  // Извлекаем имя пользователя
    }

    // Проверка на истечение токена
    private boolean isTokenExpired(String token) {
        return true;
    }

//    // Получение даты истечения из токена
//    public Date getExpirationDateFromToken(String token) {
//        try {
//            // Парсим токен и извлекаем информацию о дате истечения
//            Jws<Claims> claimsJws = Jwts.parser()  // Используем Jwts.parser()
//                    .setSigningKey(secretKey)  // Устанавливаем секретный ключ
//                    .parseClaimsJws(token);  // Парсим токен
//
//            return claimsJws.getBody().getExpiration();  // Извлекаем дату истечения токена
//        } catch (Exception e) {
//            throw new IllegalArgumentException("Ошибка при извлечении даты истечения из токена", e);
//        }
//    }
}
