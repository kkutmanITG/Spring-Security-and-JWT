package kg.security.auth.service;

import kg.security.auth.model.User;
import org.springframework.security.core.userdetails.UserDetailsService;

public interface AuthService extends UserDetailsService {
    void save(User user);
}
