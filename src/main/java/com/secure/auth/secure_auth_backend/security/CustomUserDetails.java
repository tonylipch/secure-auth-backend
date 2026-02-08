package com.secure.auth.secure_auth_backend.security;


import com.secure.auth.secure_auth_backend.entity.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.stream.Collectors;

import com.secure.auth.secure_auth_backend.entity.Role;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

@RequiredArgsConstructor
public class CustomUserDetails implements UserDetails {

    private final User user;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return user.getRoles()
                .stream()
                .map(Role::getName)                       // "ROLE_USER"
                .map(SimpleGrantedAuthority::new)        // new SimpleGrantedAuthority("ROLE_USER")
                .collect(Collectors.toSet());
    }


    public String getPassword() {
        return user.getPassword();
    }

    public User getUser() {
        return user;
    }

    public String getUsername() {
        return user.getEmail();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return !user.isLocked();
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return user.isEnabled();
    }

}
