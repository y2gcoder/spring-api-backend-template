package com.y2gcoder.app.domain.token.service;

import com.y2gcoder.app.domain.token.entity.RefreshToken;
import com.y2gcoder.app.domain.token.repository.RefreshTokenRepository;
import com.y2gcoder.app.global.error.ErrorCode;
import com.y2gcoder.app.global.error.exception.AuthenticationException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;

@Slf4j
@RequiredArgsConstructor
@Transactional(readOnly = true)
@Service
public class RefreshTokenService {

	private final RefreshTokenRepository refreshTokenRepository;

	@Transactional
	public void updateRefreshToken(Long memberId, String refreshToken, LocalDateTime refreshTokenExpireTime) {
		Optional<RefreshToken> optionalRefreshToken = refreshTokenRepository.findByMemberId(memberId);
		if (optionalRefreshToken.isPresent()) {
			RefreshToken refreshTokenEntity = optionalRefreshToken.get();
			refreshTokenEntity.updateRefreshToken(refreshToken, refreshTokenExpireTime);
			return;
		}
		RefreshToken refreshTokenEntity = RefreshToken.builder()
				.memberId(memberId)
				.refreshToken(refreshToken)
				.tokenExpirationTime(refreshTokenExpireTime)
				.build();
		refreshTokenRepository.save(refreshTokenEntity);
	}

	@Transactional
	public void removeRefreshTokenByMemberId(Long memberId) {
		Optional<RefreshToken> optionalRefreshToken = refreshTokenRepository.findByMemberId(memberId);
		if (optionalRefreshToken.isEmpty()) {
			log.info("찾고자 하는 refresh token 없음.");
			return;
		}
		RefreshToken refreshToken = optionalRefreshToken.get();
		refreshTokenRepository.delete(refreshToken);
	}

	public RefreshToken findTokenByRefreshToken(String refreshToken) {
		RefreshToken refreshTokenEntity = refreshTokenRepository
				.findByRefreshToken(refreshToken)
				.orElseThrow(() -> new AuthenticationException(ErrorCode.NOT_FOUND_REFRESH_TOKEN));
		LocalDateTime tokenExpirationTime = refreshTokenEntity.getTokenExpirationTime();
		if (tokenExpirationTime.isBefore(LocalDateTime.now())) {
			throw new AuthenticationException(ErrorCode.EXPIRED_REFRESH_TOKEN);
		}

		return refreshTokenEntity;
	}
}
