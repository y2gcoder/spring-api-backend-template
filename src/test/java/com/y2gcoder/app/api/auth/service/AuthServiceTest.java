package com.y2gcoder.app.api.auth.service;

import com.y2gcoder.app.api.auth.service.dto.SignInDto;
import com.y2gcoder.app.api.auth.service.dto.SignUpRequest;
import com.y2gcoder.app.api.auth.service.dto.TokenRefreshDto;
import com.y2gcoder.app.domain.member.constant.AuthProvider;
import com.y2gcoder.app.domain.member.constant.MemberRole;
import com.y2gcoder.app.domain.member.entity.Member;
import com.y2gcoder.app.domain.member.service.MemberService;
import com.y2gcoder.app.domain.token.entity.RefreshToken;
import com.y2gcoder.app.domain.token.service.RefreshTokenService;
import com.y2gcoder.app.global.error.ErrorCode;
import com.y2gcoder.app.global.error.exception.AuthenticationException;
import com.y2gcoder.app.global.error.exception.BusinessException;
import com.y2gcoder.app.global.jwt.constant.GrantType;
import com.y2gcoder.app.global.jwt.dto.JwtTokenDto;
import com.y2gcoder.app.global.jwt.service.JwtTokenProvider;
import com.y2gcoder.app.global.util.DateTimeUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

	@InjectMocks
	private AuthService authService;

	@Mock
	private JwtTokenProvider jwtTokenProvider;

	@Mock
	private MemberService memberService;

	@Mock
	private RefreshTokenService refreshTokenService;

	@Spy
	private PasswordEncoder passwordEncoder;

	@Test
	@DisplayName("AuthService: 회원가입, 성공")
	void whenSignUp_thenSuccess() {
		//given
		SignUpRequest signUpRequest = createSignUpRequest();
		doReturn(false).when(memberService).existsMemberByEmail(signUpRequest.getEmail());
		//when
		authService.signUp(signUpRequest);
		//then
		verify(memberService).registerMember(any(Member.class));
		verify(passwordEncoder).encode(any(String.class));
	}

	@Test
	@DisplayName("AuthService: 회원가입, 중복 이메일")
	void givenDuplicateEmail_whenSignUp_thenThrowBusinessException() {
		//given
		SignUpRequest signUpRequest = createSignUpRequest();
		doReturn(true).when(memberService).existsMemberByEmail(signUpRequest.getEmail());
		//when
		//then
		assertThatThrownBy(() -> authService.signUp(signUpRequest))
				.isInstanceOf(BusinessException.class)
				.hasMessage(ErrorCode.ALREADY_REGISTERED_MEMBER.getMessage());
	}

	@Test
	@DisplayName("AuthService: 로그인, 성공")
	void whenSignIn_thenSuccess() {
		//given
		SignInDto.Request request = createSignInRequest();
		Member member = createMember();
		JwtTokenDto jwtTokenDto = createJwtTokenDto();
		doReturn(member).when(memberService).findMemberByEmail(request.getEmail());
		doReturn(true).when(passwordEncoder).matches(request.getPassword(), member.getPassword());
		doReturn(jwtTokenDto).when(jwtTokenProvider).createJwtToken(anyString(), any());
		//when
		SignInDto.Response result = authService.signIn(request);
		//then
		assertThat(result.getAccessToken()).isEqualTo(jwtTokenDto.getAccessToken());
		assertThat(result.getRefreshToken()).isEqualTo(jwtTokenDto.getRefreshToken());

		verify(refreshTokenService).updateRefreshToken(any(), anyString(), any());
	}

	@Test
	@DisplayName("AuthService: 로그인, 아이디 패스워드 로그인 사용자가 아님.")
	void givenNotLocalMember_whenSignIn_thenThrowAuthenticationException() {
		//given
		SignInDto.Request request = createSignInRequest();
		Member member = createGoogleMember();
		doReturn(member).when(memberService).findMemberByEmail(request.getEmail());
		//when
		//then
		assertThatThrownBy(() -> authService.signIn(request))
				.isInstanceOf(AuthenticationException.class)
				.hasMessage(ErrorCode.SOCIAL_SIGN_IN_MEMBER.getMessage());
	}

	@Test
	@DisplayName("AuthService: 로그인, 비밀번호 불일치")
	void givenMismatchedPassword_whenSignIn_thenThrowAuthenticationException() {
		//given
		SignInDto.Request request = createSignInRequest("invalidPassword");
		Member member = createMember();
		doReturn(member).when(memberService).findMemberByEmail(request.getEmail());
		doReturn(false).when(passwordEncoder).matches(request.getPassword(), member.getPassword());
		//when
		//then
		assertThatThrownBy(() -> authService.signIn(request))
				.isInstanceOf(AuthenticationException.class)
				.hasMessage(ErrorCode.MISMATCH_PASSWORD.getMessage());
	}

	@Test
	@DisplayName("AuthService: 토큰 재발급, 성공")
	void whenRefreshToken_thenSuccess() {
		//given
		Member member = createMember();
		String refreshToken = "refreshToken";
		TokenRefreshDto.Request request = createTokenRefreshRequest(refreshToken);
		LocalDateTime tokenExpireTime = LocalDateTime.of(2022, 11, 1, 21, 35, 49);
		RefreshToken refreshTokenEntity = createRefreshTokenEntity(1L, refreshToken, tokenExpireTime);

		doReturn(true).when(jwtTokenProvider).validateRefreshToken(refreshToken);
		doReturn(refreshTokenEntity).when(refreshTokenService).findTokenByRefreshToken(refreshToken);
		doReturn(member).when(memberService).findMemberById(1L);

		String newAccessToken = "newAccess";
		LocalDateTime newAccessTokenExpireTime = LocalDateTime.now().plusMinutes(15L);
		Date newAccessTokenExpireTimeToDate = convertLocalDateTimeToDate(newAccessTokenExpireTime);
		doReturn(newAccessTokenExpireTimeToDate).when(jwtTokenProvider).createAccessTokenExpireTime();
		doReturn(newAccessToken)
				.when(jwtTokenProvider).createAccessToken(anyString(), any(), any());

		//when
		TokenRefreshDto.Response response = authService.refreshToken(request);

		//then
		assertThat(response.getAccessToken()).isEqualTo(newAccessToken);
		assertThat(response.getAccessTokenExpireTime())
				.isEqualTo(DateTimeUtils.convertToLocalDateTime(newAccessTokenExpireTimeToDate));
	}

	private RefreshToken createRefreshTokenEntity(Long memberId, String refreshToken, LocalDateTime tokenExpireTime) {
		return RefreshToken.builder()
				.memberId(memberId)
				.refreshToken(refreshToken)
				.tokenExpirationTime(tokenExpireTime)
				.build();
	}

	@Test
	@DisplayName("AuthService: 토큰 재발급, 토큰 유효성 검사 실패")
	void givenInvalidRefreshToken_whenRefreshToken_thenThrowAuthenticationException() {
		//given
		doReturn(false).when(jwtTokenProvider).validateRefreshToken(anyString());
		//when
		//then
		assertThatThrownBy(() -> authService.refreshToken(createTokenRefreshRequest("invalid")))
				.isInstanceOf(AuthenticationException.class)
				.hasMessage(ErrorCode.INVALID_REFRESH_TOKEN.getMessage());
	}

	private TokenRefreshDto.Request createTokenRefreshRequest(String refreshToken) {
		TokenRefreshDto.Request request = new TokenRefreshDto.Request();
		request.setRefreshToken(refreshToken);
		return request;
	}

	@Test
	@DisplayName("AuthService: 로그아웃, 성공")
	void whenSignOut_thenSuccess() {
		//given

		//when
		authService.signOut(1L);

		//then
		verify(refreshTokenService, times(1)).removeRefreshToken(1L);
	}

	private SignUpRequest createSignUpRequest() {
		SignUpRequest result = new SignUpRequest();
		result.setEmail("test@test.com");
		result.setPassword("!q2w3e4r");
		return result;
	}

	private SignInDto.Request createSignInRequest() {
		SignInDto.Request request = new SignInDto.Request();
		request.setEmail("test@test.com");
		request.setPassword("!q2w3e4r");
		return request;
	}

	private SignInDto.Request createSignInRequest(String invalidPassword) {
		SignInDto.Request request = new SignInDto.Request();
		request.setEmail("test@test.com");
		request.setPassword(invalidPassword);
		return request;
	}

	private Member createMember() {
		String encodedPw = passwordEncoder.encode("!q2w3e4r");
		return Member.builder()
				.email("test@test.com")
				.password(encodedPw)
				.role(MemberRole.USER)
				.provider(AuthProvider.local)
				.build();
	}

	private Member createGoogleMember() {
		String encodedPw = passwordEncoder.encode("!q2w3e4r");
		return Member.builder()
				.email("test@test.com")
				.password(encodedPw)
				.role(MemberRole.USER)
				.provider(AuthProvider.google)
				.build();
	}

	private JwtTokenDto createJwtTokenDto() {
		return JwtTokenDto.builder()
				.grantType(GrantType.BEARER.getType())
				.accessToken("access")
				.accessTokenExpireTime(new Date())
				.refreshToken("refresh")
				.refreshTokenExpireTime(new Date())
				.build();
	}

	private Date convertLocalDateTimeToDate(LocalDateTime dateToConvert) {
		return Date.from(dateToConvert.atZone(ZoneId.systemDefault()).toInstant());
	}

}
