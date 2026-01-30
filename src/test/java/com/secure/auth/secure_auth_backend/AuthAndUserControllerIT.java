package com.secure.auth.secure_auth_backend;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.secure.auth.secure_auth_backend.dto.auth.AuthResponseDto;
import com.secure.auth.secure_auth_backend.dto.auth.LoginRequestDto;
import com.secure.auth.secure_auth_backend.dto.auth.RegisterRequestDto;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class AuthAndUserControllerIT {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void adminPing_returns200_forAdmin() throws Exception {
        LoginRequestDto loginRequest = new LoginRequestDto(
                "admin@example.com",
                "Admin123!"
        );

        String loginResponseBody = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();

        AuthResponseDto loginResponse =
                objectMapper.readValue(loginResponseBody, AuthResponseDto.class);

        String token = loginResponse.getAccessToken();


        mockMvc.perform(get("/api/admin/ping")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(content().string("ADMIN_OK"));
    }

    @Test
    void adminPing_returns403_forNormalUser() throws Exception {
        String uniqueEmail = "user" + System.currentTimeMillis() + "@example.com";

        RegisterRequestDto registerRequest = new RegisterRequestDto(
                uniqueEmail,
                "StrongPass123!@#",   // валидный пароль
                "UserFirst",
                "UserLast"
        );

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerRequest)))
                .andExpect(status().isCreated());


        LoginRequestDto loginRequest = new LoginRequestDto(
                uniqueEmail,
                "StrongPass123!@#"
        );

        String loginResponseBody = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();

        AuthResponseDto loginResponse =
                objectMapper.readValue(loginResponseBody, AuthResponseDto.class);

        String token = loginResponse.getAccessToken();


        mockMvc.perform(get("/api/admin/ping")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isForbidden());
    }

    private String loginAndGetToken(String email, String password) throws Exception {
        LoginRequestDto request = new LoginRequestDto(email, password);

        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andReturn();

        String body = result.getResponse().getContentAsString();
        AuthResponseDto response = objectMapper.readValue(body, AuthResponseDto.class);
        return response.getAccessToken();
    }

    // ---------- /api/users/me ----------

    @Test
    void login_returns200_andToken_forValidCredentials() throws Exception {
        LoginRequestDto request = new LoginRequestDto(
                "admin@example.com",
                "Admin123!"
        );

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.tokenType").value("Bearer"));
    }

    @Test
    void login_returns400_forInvalidRequestBody() throws Exception {
        LoginRequestDto request = new LoginRequestDto(
                "",                // invalid email
                ""                 // empty password
        );

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.email").exists())
                .andExpect(jsonPath("$.errors.password").exists());
    }

    @Test
    void login_returns401_forInvalidPassword() throws Exception {
        LoginRequestDto request = new LoginRequestDto(
                "admin@example.com",
                "wrong-password"
        );

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void me_returns200_andUserProfile_forValidToken() throws Exception {
        String token = loginAndGetToken("admin@example.com", "Admin123!");

        mockMvc.perform(get("/api/users/me")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("admin@example.com"))
                .andExpect(jsonPath("$.roles").isArray());
    }

    @Test
    void me_returns403_forInvalidToken() throws Exception {
        String fakeToken = "this.is.not.a.valid.jwt";

        mockMvc.perform(get("/api/users/me")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + fakeToken))
                .andExpect(status().isForbidden());
    }

    @Test
    void register_returns201_andToken_forValidData() throws Exception {
        String uniqueEmail = "user+" + System.currentTimeMillis() + "@example.com";
        RegisterRequestDto request = new RegisterRequestDto(
                uniqueEmail,
                "NewUser123!",
                "New",
                "User"
        );

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.tokenType").value("Bearer"));
    }

    @Test
    void register_returns400_forExistingEmail() throws Exception {
        RegisterRequestDto request = new RegisterRequestDto(
                "admin@example.com",
                "Whatever123!",
                "Dup",
                "User"
        );

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void register_returns400_forWeakPassword() throws Exception {
        String uniqueEmail = "weak" + System.currentTimeMillis() + "@example.com";

        RegisterRequestDto request = new RegisterRequestDto(
                uniqueEmail,
                "123",
                "Test",
                "User"
        );

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.password").exists());
    }

}