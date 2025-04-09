package kg.security.auth.dto.response;

import kg.security.auth.model.enums.Role;
import lombok.Builder;

@Builder
public record AuthResponse(
        String username,
        Role role,
        String token
) {
}
