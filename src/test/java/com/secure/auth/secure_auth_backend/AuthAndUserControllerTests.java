package com.secure.auth.secure_auth_backend;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.secure.auth.secure_auth_backend.dto.auth.AuthResponseDto;
import com.secure.auth.secure_auth_backend.dto.auth.LoginRequestDto;
import com.secure.auth.secure_auth_backend.dto.auth.RegisterRequestDto;
import com.secure.auth.secure_auth_backend.dto.auth.TwoFactorLoginRequestDto;
import com.secure.auth.secure_auth_backend.entity.User;
import com.secure.auth.secure_auth_backend.repository.UserRepository;
import org.apache.commons.codec.binary.Base32;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.assertj.core.api.Assertions.assertThat;


import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.time.Instant;

@SpringBootTest
@AutoConfigureMockMvc
class AuthAndUserControllerTests {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserRepository userRepository;

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
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.requiresTwoFactor").value(false));
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
                .andExpect(jsonPath("$.roles").isArray())
                .andExpect(jsonPath("$.twoFactorEnabled").value(false));
    }

    @Test
    void me_returns403_forInvalidToken() throws Exception {
        String fakeToken = "this.is.not.a.valid.jwt";

        mockMvc.perform(get("/api/users/me")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + fakeToken))
                .andExpect(status().isForbidden());
    }

    @Test
    void changePassword_returns204_forValidRequest() throws Exception {
        String email = "changepw+" + System.currentTimeMillis() + "@example.com";
        String initialPassword = "InitPass123!";

        RegisterRequestDto registerRequest = new RegisterRequestDto(
                email,
                initialPassword,
                "Change",
                "Password"
        );

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerRequest)))
                .andExpect(status().isCreated());

        String token = loginAndGetToken(email, initialPassword);

        String newPassword = "NewPass123!";
        String body = """
                {
                  "currentPassword": "%s",
                  "newPassword": "%s"
                }
                """.formatted(initialPassword, newPassword);

        mockMvc.perform(post("/api/users/change-password")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isNoContent());

        LoginRequestDto loginRequest = new LoginRequestDto(email, newPassword);
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty());
    }

    @Test
    void changePassword_returns400_forWrongCurrentPassword() throws Exception {
        String email = "changepw2+" + System.currentTimeMillis() + "@example.com";
        String initialPassword = "InitPass123!";

        RegisterRequestDto registerRequest = new RegisterRequestDto(
                email,
                initialPassword,
                "Change",
                "Password"
        );

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerRequest)))
                .andExpect(status().isCreated());

        String token = loginAndGetToken(email, initialPassword);

        String body = """
                {
                  "currentPassword": "WrongPass123!",
                  "newPassword": "NewPass123!"
                }
                """;

        mockMvc.perform(post("/api/users/change-password")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isBadRequest());
    }

    @Test
    void setup2fa_verify_and_disable_workflow() throws Exception {
        String email = "twofactor-setup+" + System.currentTimeMillis() + "@example.com";
        String password = "StrongPass123!@#";

        RegisterRequestDto registerRequest = new RegisterRequestDto(
                email,
                password,
                "Two",
                "Factor"
        );

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerRequest)))
                .andExpect(status().isCreated());

        String token = loginAndGetToken(email, password);

        String setupBody = mockMvc.perform(post("/api/users/2fa/setup")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.secret").isNotEmpty())
                .andExpect(jsonPath("$.otpAuthUri").isNotEmpty())
                .andReturn()
                .getResponse()
                .getContentAsString();

        String secret = objectMapper.readTree(setupBody).get("secret").asText();
        String code = generateTotp(secret);

        String verifyBody = """
                {
                  "code": "%s"
                }
                """.formatted(code);

        mockMvc.perform(post("/api/users/2fa/verify")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(verifyBody))
                .andExpect(status().isNoContent());

        String disableCode = generateTotp(secret);
        String disableBody = """
                {
                  "code": "%s"
                }
                """.formatted(disableCode);

        mockMvc.perform(post("/api/users/2fa/disable")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(disableBody))
                .andExpect(status().isNoContent());
    }

    // ---------- OAuth2 ----------
    @Test
    void oauth2Authorization_redirectsToGoogle() throws Exception {
        mockMvc.perform(get("/oauth2/authorization/google"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().exists("Location"))
                .andExpect(header().string("Location",
                        org.hamcrest.Matchers.containsString("accounts.google.com")));
    }

    @Test
    void oauth2Callback_redirects_withoutValidCode() throws Exception {
        mockMvc.perform(get("/login/oauth2/code/google")
                        .param("code", "invalid-code"))
                .andExpect(status().is3xxRedirection());
    }

    @Test
    void oauth2Endpoints_arePublic() throws Exception {
        mockMvc.perform(get("/oauth2/authorization/google"))
                .andExpect(status().is3xxRedirection());

        mockMvc.perform(get("/login/oauth2/code/google"))
                .andExpect(result -> {
                    int status = result.getResponse().getStatus();
                    assertThat(status).isNotEqualTo(403);
                });
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
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.requiresTwoFactor").value(false));
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

    @Test
    void login_returns2faChallenge_whenTwoFactorEnabled() throws Exception {
        String email = "twofactor+" + System.currentTimeMillis() + "@example.com";

        RegisterRequestDto registerRequest = new RegisterRequestDto(
                email,
                "StrongPass123!@#",
                "Two",
                "Factor"
        );

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerRequest)))
                .andExpect(status().isCreated());

        User user = userRepository.findByEmail(email).orElseThrow();
        String secret = "JBSWY3DPEHPK3PXP";
        user.setTwoFactorSecret(secret);
        user.setTwoFactorEnabled(true);
        userRepository.save(user);

        LoginRequestDto loginRequest = new LoginRequestDto(email, "StrongPass123!@#");

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.requiresTwoFactor").value(true))
                .andExpect(jsonPath("$.tempToken").isNotEmpty());
    }

    @Test
    void login2fa_returnsToken_whenCodeValid() throws Exception {
        String email = "twofactor2+" + System.currentTimeMillis() + "@example.com";

        RegisterRequestDto registerRequest = new RegisterRequestDto(
                email,
                "StrongPass123!@#",
                "Two",
                "Factor"
        );

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerRequest)))
                .andExpect(status().isCreated());

        User user = userRepository.findByEmail(email).orElseThrow();
        String secret = "JBSWY3DPEHPK3PXP";
        user.setTwoFactorSecret(secret);
        user.setTwoFactorEnabled(true);
        userRepository.save(user);

        LoginRequestDto loginRequest = new LoginRequestDto(email, "StrongPass123!@#");
        String loginResponseBody = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.requiresTwoFactor").value(true))
                .andReturn()
                .getResponse()
                .getContentAsString();

        AuthResponseDto loginResponse =
                objectMapper.readValue(loginResponseBody, AuthResponseDto.class);

        String tempToken = loginResponse.getTempToken();
        String code = generateTotp(secret);

        TwoFactorLoginRequestDto twoFactorRequest = new TwoFactorLoginRequestDto(tempToken, code);

        mockMvc.perform(post("/api/auth/login/2fa")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(twoFactorRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.requiresTwoFactor").value(false));
    }

    @Test
    void login2fa_returns401_whenCodeInvalid() throws Exception {
        String email = "twofactor3+" + System.currentTimeMillis() + "@example.com";

        RegisterRequestDto registerRequest = new RegisterRequestDto(
                email,
                "StrongPass123!@#",
                "Two",
                "Factor"
        );

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerRequest)))
                .andExpect(status().isCreated());

        User user = userRepository.findByEmail(email).orElseThrow();
        String secret = "JBSWY3DPEHPK3PXP";
        user.setTwoFactorSecret(secret);
        user.setTwoFactorEnabled(true);
        userRepository.save(user);

        LoginRequestDto loginRequest = new LoginRequestDto(email, "StrongPass123!@#");
        String loginResponseBody = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.requiresTwoFactor").value(true))
                .andReturn()
                .getResponse()
                .getContentAsString();

        AuthResponseDto loginResponse =
                objectMapper.readValue(loginResponseBody, AuthResponseDto.class);

        String tempToken = loginResponse.getTempToken();

        TwoFactorLoginRequestDto twoFactorRequest = new TwoFactorLoginRequestDto(tempToken, "000000");

        mockMvc.perform(post("/api/auth/login/2fa")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(twoFactorRequest)))
                .andExpect(status().isUnauthorized());
    }

    private String generateTotp(String secretBase32) throws Exception {
        Base32 base32 = new Base32();
        byte[] key = base32.decode(secretBase32);

        long timeWindow = Instant.now().getEpochSecond() / 30;
        byte[] data = ByteBuffer.allocate(8).putLong(timeWindow).array();

        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(new SecretKeySpec(key, "HmacSHA1"));
        byte[] hash = mac.doFinal(data);

        int offset = hash[hash.length - 1] & 0x0F;
        int binary =
                ((hash[offset] & 0x7F) << 24) |
                        ((hash[offset + 1] & 0xFF) << 16) |
                        ((hash[offset + 2] & 0xFF) << 8) |
                        (hash[offset + 3] & 0xFF);

        int otp = binary % 1_000_000;
        return String.format("%06d", otp);
    }

}
