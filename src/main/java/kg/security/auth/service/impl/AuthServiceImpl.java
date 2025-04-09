package kg.security.auth.service.impl;

import kg.security.auth.config.jwt.JwtUtil;
import kg.security.auth.dto.request.AuthRequest;
import kg.security.auth.dto.request.RegisterRequest;
import kg.security.auth.dto.response.AuthResponse;
import kg.security.auth.model.User;
import kg.security.auth.repository.UserRepository;
import kg.security.auth.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final AuthenticationManager authenticationManager;

    // Регистрация нового пользователя
    @Override
    public AuthResponse register(RegisterRequest request) {
        // Проверяем, нет ли уже пользователя с таким email/username
        if (userRepository.findByUsername(request.username()).isPresent()) {
            throw new RuntimeException("User already exists");
        }

        // Создаём пользователя
        User user = User.builder()
                .username(request.username())
                .password(passwordEncoder.encode(request.password()))
                .role(request.role())
                .build();

        userRepository.save(user);

        // Генерируем JWT токен
        String jwtToken = jwtUtil.generateToken(user.getUsername());
        return AuthResponse.builder()
                .username(user.getUsername())
                .role(user.getRole())
                .token(jwtToken)
                .build();
    }

    // Аутентификация (вход)
    @Override
    public AuthResponse login(AuthRequest request) {
        // Проверяем логин и пароль
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.username(),
                        request.password()
                )
        );

        // Если аутентификация успешна, генерируем токен
        User user = userRepository.findByUsername(request.username())
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        String jwtToken = jwtUtil.generateToken(user.getUsername());
        return AuthResponse.builder()
                .token(jwtToken)
                .build();
    }

    // Загрузка пользователя для Spring Security
    // Реализация метода из UserDetailsService
    @Override
    public UserDetails loadUserByUsername(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPassword(),
                user.getAuthorities()
        );
    }
}