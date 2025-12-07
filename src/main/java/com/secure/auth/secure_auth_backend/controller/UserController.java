package com.secure.auth.secure_auth_backend.controller;


import com.secure.auth.secure_auth_backend.dto.user.UserProfileDto;
import com.secure.auth.secure_auth_backend.entity.User;
import com.secure.auth.secure_auth_backend.entity.Role;
import com.secure.auth.secure_auth_backend.security.CustomUserDetails;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
@Slf4j
public class UserController {
    @GetMapping("/me")
    public UserProfileDto me() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Object principal = authentication.getPrincipal();

        if (!(principal instanceof CustomUserDetails customUserDetails)) {
            log.warn("Principal is not CustomUserDetails: {}", principal);
            throw new IllegalStateException("Unexpected principal type");
        }

        User user = customUserDetails.getUser();

        Set<String> roles = user.getRoles().stream()
                .map(Role::getName)
                .collect(Collectors.toSet());

        return new UserProfileDto(
                user.getEmail(),
                user.getFirstName(),
                user.getLastName(),
                roles
        );
    }
}
