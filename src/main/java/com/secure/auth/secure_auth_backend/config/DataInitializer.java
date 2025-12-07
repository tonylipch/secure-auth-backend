package com.secure.auth.secure_auth_backend.config;


import com.secure.auth.secure_auth_backend.entity.AuthProvider;
import com.secure.auth.secure_auth_backend.entity.Role;
import com.secure.auth.secure_auth_backend.entity.User;
import com.secure.auth.secure_auth_backend.repository.RoleRepository;
import com.secure.auth.secure_auth_backend.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Set;

@Configuration
@RequiredArgsConstructor
public class DataInitializer {
    private final RoleRepository roleRepository;
    private final UserRepository userRepository;

    @Bean
    public CommandLineRunner initData(PasswordEncoder passwordEncoder) {
        return args -> {
            //Roles
            Role userRole = roleRepository.findByName("ROLE_USER")
                    .orElseGet(() -> roleRepository.save(
                            Role.builder().name("ROLE_USER").build()
                    ));

            Role adminRole = roleRepository.findByName("ROLE_ADMIN")
                    .orElseGet(() -> roleRepository.save(
                            Role.builder().name("ROLE_ADMIN").build()
                    ));

            //AdminUser
            String adminEmail = "admin@example.com";

            if (!userRepository.existsByEmail(adminEmail)) {
                User admin = User.builder()
                        .email(adminEmail)
                        .password(passwordEncoder.encode("Admin123!"))
                        .firstName("Admin")
                        .lastName("User")
                        .enabled(true)
                        .locked(false)
                        .provider(AuthProvider.LOCAL)
                        .roles(Set.of(adminRole, userRole))
                        .build();

                userRepository.save(admin);
            }
        };
    }


}
