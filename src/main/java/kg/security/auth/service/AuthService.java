package kg.security.auth.service;

import kg.security.auth.dto.request.AuthRequest;
import kg.security.auth.dto.request.RegisterRequest;
import kg.security.auth.dto.response.AuthResponse;
import org.springframework.security.core.userdetails.UserDetailsService;

public interface AuthService extends UserDetailsService {
    AuthResponse register(RegisterRequest request); // Регистрация
    AuthResponse login(AuthRequest request);        // Вход
}
