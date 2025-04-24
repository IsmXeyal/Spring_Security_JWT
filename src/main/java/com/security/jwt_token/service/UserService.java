package com.security.jwt_token.service;

import com.security.jwt_token.dto.UserRegisterDto;
import com.security.jwt_token.model.User;
import org.springframework.security.core.userdetails.UserDetailsService;

import java.util.Optional;

public interface UserService extends UserDetailsService {
    Optional<User> getByUsername(String username);
    User createUser(UserRegisterDto registerDto);
}
