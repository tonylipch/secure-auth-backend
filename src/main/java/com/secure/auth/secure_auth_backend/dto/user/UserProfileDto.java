package com.secure.auth.secure_auth_backend.dto.user;


import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.Set;

@Data
@AllArgsConstructor
public class UserProfileDto {
    private String email;
    private String firstName;
    private String lastName;
    private Set<String> roles;
}
