package com.secure.auth.secure_auth_backend.dto.auth;


import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuthResponseDto {
    private String accessToken;
    private String tokenType;
    private Boolean requiresTwoFactor;
    private String tempToken;
}
