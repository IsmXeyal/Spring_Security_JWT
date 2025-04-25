package com.security.jwt_token.service.impl;

import com.security.jwt_token.dto.JwtAuthenticationResponseDto;
import com.security.jwt_token.dto.RefreshTokenDto;
import com.security.jwt_token.dto.UserLoginDto;
import com.security.jwt_token.dto.UserRegisterDto;
import com.security.jwt_token.exceptions.InvalidCredentialsException;
import com.security.jwt_token.exceptions.RefreshTokenNotFoundException;
import com.security.jwt_token.exceptions.TokenExpiredException;
import com.security.jwt_token.model.Token;
import com.security.jwt_token.model.User;
import com.security.jwt_token.repository.*;
import com.security.jwt_token.service.AuthenticationService;
import com.security.jwt_token.service.JwtService;
import com.security.jwt_token.service.UserService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;

@Service
@RequiredArgsConstructor
public class AuthenticationServiceImpl implements AuthenticationService {
    private static final Logger logger = LoggerFactory.getLogger(AuthenticationServiceImpl.class);

    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
    private final JwtService jwtService;
    private final UserService userService;

    private final AuthenticationManager authenticationManager;

    @Value("${token.access.token.expiration}")
    private long accessTokenExpiration;

    @Transactional
    @Override
    public JwtAuthenticationResponseDto login(UserLoginDto request) {
        logger.info("Attempting login for user: {}", request.getUsername());
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
            );
        } catch (Exception e) {
            logger.warn("Login failed: Invalid credentials for user {}", request.getUsername());
            throw new InvalidCredentialsException();
        }

        var user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> {
                    logger.warn("Login failed: User not found {}", request.getUsername());
                    return new InvalidCredentialsException();
                });

        var jwt = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        var expiresAt = new Date(System.currentTimeMillis() + accessTokenExpiration);

        if (tokenRepository.findByUserId(user.getId()).isPresent()) {
            tokenRepository.updateTokenByUserId(jwt, refreshToken, expiresAt, user.getId());
            logger.info("Updated existing token for user: {}", user.getUsername());
        } else {
            tokenRepository.save(new Token(jwt, refreshToken, expiresAt, user, true));
            logger.info("Saved new token for user: {}", user.getUsername());
        }

        return JwtAuthenticationResponseDto.builder()
                .token(jwt)
                .refreshToken(refreshToken)
                .expiresAt(expiresAt)
                .build();
    }

    // This method is called when the user sends a refresh token to get a new access token (and a new refresh token),
    // without re-logging in.
    @Override
    public JwtAuthenticationResponseDto refreshToken(RefreshTokenDto request) {
        logger.info("Refreshing token using refreshToken: {}", request.getRefreshToken());

        Token oldToken = tokenRepository.findByRefreshToken(request.getRefreshToken())
                .orElseThrow(() -> {
                    logger.warn("Refresh token not found: {}", request.getRefreshToken());
                    return new RefreshTokenNotFoundException(request.getRefreshToken());
                });

        if (oldToken.getExpiresAt().after(new Date()) && oldToken.getIsActive()) {
            var user = oldToken.getUser();
            var newAccessToken = jwtService.generateToken(user);
            var newRefreshToken = jwtService.generateRefreshToken(user);
            var expiresAt = new Date(System.currentTimeMillis() + accessTokenExpiration);
            oldToken.setIsActive(false);
            tokenRepository.save(oldToken);
            logger.info("Old token deactivated for user: {}", user.getUsername());

            tokenRepository.findByUserId(user.getId())
                    .ifPresentOrElse(
                            existingToken -> {
                                tokenRepository.updateTokenByUserId(newAccessToken, newRefreshToken, expiresAt, user.getId());
                                logger.info("Updated token for user: {}", user.getUsername());
                            },
                            () -> {
                                tokenRepository.save(new Token(newAccessToken, newRefreshToken, expiresAt, user, true));
                                logger.info("Saved new tokens for user: {}", user.getUsername());
                            }
                    );

            return JwtAuthenticationResponseDto.builder()
                    .token(newAccessToken)
                    .refreshToken(newRefreshToken)
                    .expiresAt(expiresAt)
                    .build();
        } else {
            logger.warn("Refresh token expired or inactive: {}", request.getRefreshToken());
            tokenRepository.delete(oldToken);
            throw new TokenExpiredException("The refresh token is expired or inactive.");
        }
    }

    @Override
    public JwtAuthenticationResponseDto register(UserRegisterDto registerDto){
        logger.info("Registering new user: {}", registerDto.getUsername());

        User user = userService.createUser(registerDto);

        // Create accessToken and refreshToken
        String accessToken = jwtService.generateToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);
        Date expiresAt = new Date(System.currentTimeMillis() + accessTokenExpiration);

        tokenRepository.save(new Token(accessToken, refreshToken, expiresAt, user, true));
        logger.info("Generated and saved tokens for new user: {}", user.getUsername());

        return JwtAuthenticationResponseDto.builder()
                .token(accessToken)
                .refreshToken(refreshToken)
                .expiresAt(expiresAt)
                .build();
    }
}
