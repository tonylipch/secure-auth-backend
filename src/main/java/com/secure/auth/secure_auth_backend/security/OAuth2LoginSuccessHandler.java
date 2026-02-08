package com.secure.auth.secure_auth_backend.security;


import com.secure.auth.secure_auth_backend.entity.AuthProvider;
import com.secure.auth.secure_auth_backend.entity.Role;
import com.secure.auth.secure_auth_backend.entity.User;
import com.secure.auth.secure_auth_backend.repository.RoleRepository;
import com.secure.auth.secure_auth_backend.repository.UserRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Optional;
import java.util.Set;

@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final JwtService jwtService;


    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) throws IOException {

        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();

        String email = oAuth2User.getAttribute("email");
        String providerId = oAuth2User.getAttribute("sub");
        String givenName = Optional
                .ofNullable(oAuth2User.<String>getAttribute("given_name"))
                .orElse("");
        String familyName = Optional
                .ofNullable(oAuth2User.<String>getAttribute("family_name"))
                .orElse("");

        log.info("Successful Google login for email={}", email);

        // Ищем юзера по email
        User user = userRepository.findByEmail(email)
                .orElseGet(() -> {
                    log.info("No local user for {}, creating new with provider=GOOGLE", email);
                    Role userRole = roleRepository.findByName("ROLE_USER")
                            .orElseThrow(() -> new IllegalStateException("ROLE_USER not found"));
                    return userRepository.save(User.builder()
                            .email(email)
                            .firstName(givenName)
                            .lastName(familyName)
                            .enabled(true)
                            .locked(false)
                            .provider(AuthProvider.GOOGLE)
                            .providerId(providerId)
                            .roles(Set.of(userRole))
                            .build());
                });
        CustomUserDetails userDetails = new CustomUserDetails(user);
        String token = jwtService.generateAccessToken(userDetails);

        response.setContentType("application/json");
        response.getWriter().write("""
                {"accessToken": "%s", "tokenType": "Bearer"}
                """.formatted(token));
        response.getWriter().flush();
    }
}
