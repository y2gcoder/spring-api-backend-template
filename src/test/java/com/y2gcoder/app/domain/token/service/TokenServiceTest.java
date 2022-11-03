package com.y2gcoder.app.domain.token.service;

import com.y2gcoder.app.domain.token.entity.RefreshToken;
import com.y2gcoder.app.domain.token.repository.RefreshTokenRepository;
import com.y2gcoder.app.global.error.ErrorCode;
import com.y2gcoder.app.global.error.exception.AuthenticationException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class TokenServiceTest {
	@InjectMocks
	private TokenService tokenService;

	@Mock
	private RefreshTokenRepository refreshTokenRepository;

	@Test
	@DisplayName("RefreshTokenService: updateRefreshToken, 신규 토큰 저장 성공")
	void givenNotFoundMemberId_whenUpdateRefreshToken_thenSuccess() {
		//given
		Long memberId = 1L;
		String refreshToken = "refreshToken";
		LocalDateTime tokenExpireTime = LocalDateTime.now();
		doReturn(Optional.empty()).when(refreshTokenRepository).findByMemberId(anyLong());

		//when
		tokenService.updateRefreshToken(memberId, refreshToken, tokenExpireTime);

		//then
		verify(refreshTokenRepository, times(1)).save(any(RefreshToken.class));
	}

	@Test
	@DisplayName("RefreshTokenService: updateRefreshToken, 기존 토큰 업데이트, 성공")
	void givenAlreadyExistsRefreshToken_whenUpdateRefreshToken_thenUpdateSuccess() {
		//given
		Long memberId = 1L;
		String oldRefreshToken = "refreshToken";
		LocalDateTime oldTokenExpireTime = LocalDateTime.of(2022, 11, 1, 21, 35, 49);
		RefreshToken refreshTokenEntity = createRefreshTokenEntity(memberId, oldRefreshToken, oldTokenExpireTime);
		doReturn(Optional.of(refreshTokenEntity)).when(refreshTokenRepository).findByMemberId(memberId);

		//when
		String newRefreshToken = "newRefreshToken";
		LocalDateTime newTokenExpireTime = LocalDateTime.of(2022, 11, 1, 21, 36, 37);
	  tokenService.updateRefreshToken(memberId, newRefreshToken, newTokenExpireTime);

		//then
		assertThat(refreshTokenEntity.getRefreshToken()).isEqualTo(newRefreshToken);
		assertThat(refreshTokenEntity.getTokenExpirationTime()).isEqualTo(newTokenExpireTime);
	}

	@Test
	@DisplayName("RefreshTokenService: removeRefreshToken, 삭제, 성공")
	void givenExistsRefreshToken_whenRemoveRefreshToken_thenSuccess() {
		//given
		Long memberId = 1L;
		String refreshToken = "refreshToken";
		LocalDateTime tokenExpireTime = LocalDateTime.of(2022, 11, 1, 21, 35, 49);
		RefreshToken refreshTokenEntity = createRefreshTokenEntity(memberId, refreshToken, tokenExpireTime);
		doReturn(Optional.of(refreshTokenEntity)).when(refreshTokenRepository).findByMemberId(memberId);

		//when
		tokenService.removeRefreshToken(memberId);

		//then
		verify(refreshTokenRepository, times(1)).delete(any(RefreshToken.class));
	}

	@Test
	@DisplayName("RefreshTokenService: removeRefreshToken, 이미 토큰 없음, 성공")
	void givenNotExistsRefreshToken_whenRemoveRefreshToken_thenSuccess() {
		//given
		Long memberId = 1L;
		doReturn(Optional.empty()).when(refreshTokenRepository).findByMemberId(memberId);
		//when
		tokenService.removeRefreshToken(memberId);

		//then
		verify(refreshTokenRepository, times(0)).delete(any(RefreshToken.class));
	}

	@Test
	@DisplayName("RefreshTokenService: findTokenByRefreshToken, 성공")
	void whenFindTokenByRefreshToken_thenSuccess() {
		//given
		Long memberId = 1L;
		String refreshToken = "refreshToken";
		LocalDateTime tokenExpireTime = LocalDateTime.now().plusWeeks(2);
		RefreshToken refreshTokenEntity = createRefreshTokenEntity(memberId, refreshToken, tokenExpireTime);
		doReturn(Optional.of(refreshTokenEntity)).when(refreshTokenRepository).findByRefreshToken(refreshToken);

		//when
		RefreshToken result = tokenService.findTokenByRefreshToken(refreshToken);

		//then
		assertThat(result.getRefreshToken()).isEqualTo(refreshToken);
	}

	@Test
	@DisplayName("RefreshTokenService: findTokenByRefreshToken, refreshToken을 찾을 수 없음, 실패")
	void whenFindTokenByRefreshToken_thenNotFoundRefreshToken() {
		//given
		String refreshToken = "refreshToken";
		doReturn(Optional.empty()).when(refreshTokenRepository).findByRefreshToken(refreshToken);

		//when
		//then
		assertThatThrownBy(() -> tokenService.findTokenByRefreshToken(refreshToken))
				.isInstanceOf(AuthenticationException.class)
				.hasMessage(ErrorCode.NOT_FOUND_REFRESH_TOKEN.getMessage());
	}

	@Test
	@DisplayName("RefreshTokenService: findTokenByRefreshToken, refreshToken 시간이 만료됨.")
	void givenExpiredRefreshToken_whenFindTokenByRefreshToken_thenException() {
		//given
		Long memberId = 1L;
		String refreshToken = "refreshToken";
		LocalDateTime tokenExpireTime = LocalDateTime.now().minusSeconds(1);
		RefreshToken refreshTokenEntity = createRefreshTokenEntity(memberId, refreshToken, tokenExpireTime);
		doReturn(Optional.of(refreshTokenEntity)).when(refreshTokenRepository).findByRefreshToken(refreshToken);

		//when
		//then
		assertThatThrownBy(() -> tokenService.findTokenByRefreshToken(refreshToken))
				.isInstanceOf(AuthenticationException.class)
				.hasMessage(ErrorCode.EXPIRED_REFRESH_TOKEN.getMessage());
	}

	private RefreshToken createRefreshTokenEntity(Long memberId, String refreshToken, LocalDateTime tokenExpireTime) {
		return RefreshToken.builder()
				.memberId(memberId)
				.refreshToken(refreshToken)
				.tokenExpirationTime(tokenExpireTime)
				.build();
	}

}
