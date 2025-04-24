package com.security.jwt_token.repository;

import com.security.jwt_token.model.*;
import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Date;
import java.util.List;
import java.util.Optional;

@Repository
public interface TokenRepository extends JpaRepository<Token, Long> {
    Optional<Token> findByToken(String token);

    Optional<List<Token>> findAllByUserAndIsActive(User user, Boolean isActive);

    Optional<Token> findByRefreshToken(String refreshToken);
    Optional<Token> findByUserId(Long userId);

    @Modifying
    @Transactional
    @Query("UPDATE Token t SET t.token = :token, t.refreshToken = :refreshToken, t.expiresAt = :expiresAt, t.isActive = true WHERE t.user.id = :userId")
    void updateTokenByUserId(@Param("token") String token,
                             @Param("refreshToken") String refreshToken,
                             @Param("expiresAt") Date expiresAt,
                             @Param("userId") Long userId);
}
