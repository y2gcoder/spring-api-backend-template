package com.y2gcoder.app.domain.token.repository;

import com.y2gcoder.app.domain.token.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

	Optional<RefreshToken> findByMemberId(Long memberId);

	Optional<RefreshToken> findByRefreshToken(String refreshToken);
}
