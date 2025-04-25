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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;

@Service
public class UserServiceImpl implements UserService, UserDetailsService {
    private static final Logger logger = LoggerFactory.getLogger(UserServiceImpl.class);
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserServiceImpl(UserRepository userRepository,  PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        logger.info("Loading user by username: {}", username);
        Optional<User> user = userRepository.findByUsername(username);
        return user.orElseThrow(() -> {
            logger.warn("User not found with username: {}", username);
            return new UsernameNotFoundException("User not found with username: " + username);
        });
    }

    @Override
    public Optional<User> getByUsername(String username) {
        logger.debug("Retrieving user by username: {}", username);
        return userRepository.findByUsername(username);
    }

    @Override
    public User createUser(UserRegisterDto request) {
        logger.info("Attempting to register user: {}", request.getUsername());
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
            logger.warn(message.toString().trim());
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

        User savedUser = userRepository.save(newUser);
        logger.info("User registered successfully: {}", savedUser.getUsername());

        return savedUser;
    }
}