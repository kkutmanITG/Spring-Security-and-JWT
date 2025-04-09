package kg.security.auth.dto.request;

public record AuthRequest(
        String username,
        String password
) {
}
