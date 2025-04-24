package com.security.jwt_token.service.impl;

import com.security.jwt_token.dto.UserRegisterDto;
import com.security.jwt_token.exceptions.UserAlreadyExistsException;
import com.security.jwt_token.model.User;
import com.security.jwt_token.repository.UserRepository;
import com.security.jwt_token.service.UserService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserServiceImpl implements UserService, UserDetailsService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserServiceImpl(UserRepository userRepository,  PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<User> user = userRepository.findByUsername(username);
        return user.orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));
    }

    @Override
    public Optional<User> getByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    @Override
    public User createUser(UserRegisterDto request) {
        // Check if the username or email already exists
        if (userRepository.existsByUsername(request.getUsername()) || userRepository.existsByEmail(request.getEmail())) {
            StringBuilder message = new StringBuilder("Registration failed: ");

            boolean usernameExists = userRepository.existsByUsername(request.getUsername());
            boolean emailExists = userRepository.existsByEmail(request.getEmail());

            if (usernameExists) {
                message.append("Username '").append(request.getUsername()).append("' already exists. ");
            }
            if (emailExists) {
                message.append("Email '").append(request.getEmail()).append("' already exists.");
            }
            throw new UserAlreadyExistsException(message.toString().trim());
        }

        User newUser = User.builder()
                .firstName(request.getFirstName())
                .email(request.getEmail())
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .roles(request.getRoles())
                .accountNonExpired(true)
                .credentialsNonExpired(true)
                .enabled(true)
                .accountNonLocked(true)
                .build();

        return userRepository.save(newUser);
    }
}