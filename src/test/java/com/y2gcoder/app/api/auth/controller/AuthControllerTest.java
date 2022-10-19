package com.y2gcoder.app.api.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.y2gcoder.app.api.auth.service.AuthService;
import com.y2gcoder.app.api.auth.service.dto.SignInDto;
import com.y2gcoder.app.api.auth.service.dto.SignUpRequest;
import com.y2gcoder.app.global.jwt.constant.GrantType;
import com.y2gcoder.app.global.jwt.dto.JwtTokenDto;
import com.y2gcoder.app.global.util.CookieUtils;
import com.y2gcoder.app.global.util.RefreshTokenCookieUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import javax.servlet.http.Cookie;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
class AuthControllerTest {
	@InjectMocks
	private AuthController authController;

	@Mock
	private AuthService authService;

	@Mock
	private RefreshTokenCookieUtils refreshTokenCookieUtils;

	private MockMvc mockMvc;
	private ObjectMapper objectMapper;

	private static final String REFRESH_TOKEN_COOKIE_NAME = "refreshtoken";

	@BeforeEach
	public void beforeEach() {
		mockMvc = MockMvcBuilders
				.standaloneSetup(authController)
				.build();
		objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());
	}

	@Test
	@DisplayName("AuthController(단위): 회원가입, 성공")
	void whenSignUp_thenSuccess() throws Exception {
		//given
		SignUpRequest request = createSignUpRequest();

		//when
		ResultActions resultActions = mockMvc.perform(
				MockMvcRequestBuilders.post("/api/auth/sign-up")
						.contentType(MediaType.APPLICATION_JSON)
						.content(objectMapper.writeValueAsString(request))
		);

		//then
		resultActions.andExpect(status().isCreated()).andReturn();
		verify(authService).signUp(any(SignUpRequest.class));
	}

	private SignUpRequest createSignUpRequest() {
		SignUpRequest result = new SignUpRequest();
		result.setEmail("test@test.com");
		result.setPassword("!q2w3e4r");
		return result;
	}

	@Test
	@DisplayName("AuthController(단위): 로그인, 성공")
	void whenSignIn_thenSuccess() throws Exception {
		//given
		SignInDto.Request request = createSignInRequest();
		JwtTokenDto jwtTokenDto = createJwtTokenDto();
		doReturn(jwtTokenDto).when(authService).signIn(any(SignInDto.Request.class));
		doReturn(createRefreshTokenCookie(jwtTokenDto.getRefreshToken()).toString())
				.when(refreshTokenCookieUtils)
				.generateRefreshTokenCookie(jwtTokenDto.getRefreshToken());
		//when
		ResultActions resultActions = mockMvc.perform(
				MockMvcRequestBuilders.post("/api/auth/sign-in")
						.contentType(MediaType.APPLICATION_JSON)
						.content(objectMapper.writeValueAsString(request))
		);

		//then
		MvcResult mvcResult = resultActions.andExpect(status().isOk()).andReturn();
		SignInDto.Response result = objectMapper
				.readValue(mvcResult.getResponse().getContentAsString(), SignInDto.Response.class);
		Cookie resultCookie = mvcResult.getResponse().getCookie(REFRESH_TOKEN_COOKIE_NAME);
		assertThat(result.getAccessToken()).isEqualTo(jwtTokenDto.getAccessToken());
		assertThat(resultCookie).isNotNull();
	}

	private SignInDto.Request createSignInRequest() {
		SignInDto.Request request = new SignInDto.Request();
		request.setEmail("test@test.com");
		request.setPassword("!q2w3e4r");
		return request;
	}

	@Test
	@DisplayName("AuthController(단위): 토큰 리프레시, 성공")
	void whenRefreshToken_thenSuccess() throws Exception {
		//given
		String refreshToken = "refresh";
		String newRefreshToken = "newRefresh";
		JwtTokenDto jwtTokenDto = createJwtTokenDtoWithNewRefreshToken(newRefreshToken);
		doReturn(jwtTokenDto).when(authService).refreshToken(refreshToken);
		ResponseCookie refreshTokenCookie = createRefreshTokenCookie(jwtTokenDto.getRefreshToken());
		doReturn(refreshTokenCookie.toString())
				.when(refreshTokenCookieUtils)
				.generateRefreshTokenCookie(jwtTokenDto.getRefreshToken());

		//when
		ResponseCookie requestRefreshTokenCookie = createRefreshTokenCookie(refreshToken);
		ResultActions resultActions = mockMvc.perform(
				MockMvcRequestBuilders.post("/api/auth/refresh")
						.cookie(new Cookie(requestRefreshTokenCookie.getName(), requestRefreshTokenCookie.getValue()))
		);
		//then
		MvcResult mvcResult = resultActions.andExpect(status().isOk()).andReturn();
		JwtTokenDto result = objectMapper.readValue(mvcResult.getResponse().getContentAsString(), JwtTokenDto.class);
		Cookie resultCookie = mvcResult.getResponse().getCookie(REFRESH_TOKEN_COOKIE_NAME);
		assertThat(result.getRefreshToken()).isEqualTo(newRefreshToken);
		assertThat(resultCookie).isNotNull();
		assertThat(resultCookie.getMaxAge()).isEqualTo(3600);
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

	private JwtTokenDto createJwtTokenDtoWithNewRefreshToken(String newRefreshToken) {
		return JwtTokenDto.builder()
				.grantType(GrantType.BEARER.getType())
				.accessToken("access")
				.accessTokenExpireTime(new Date())
				.refreshToken(newRefreshToken)
				.refreshTokenExpireTime(new Date())
				.build();
	}

	private ResponseCookie createRefreshTokenCookie(String refreshToken) {
		return CookieUtils
				.generateResponseCookie(
						REFRESH_TOKEN_COOKIE_NAME,
						refreshToken,
						3600
				);
	}

	@Test
	@DisplayName("AuthController(단위): 로그아웃, 성공")
	void whenSignOut_thenSuccess() throws Exception {
		//given
		String refreshToken = "refresh";
		ResponseCookie signOutCookie = createSignOutCookie();
		doReturn(signOutCookie.toString()).when(refreshTokenCookieUtils).generateSignOutCookie();
		//when
		ResponseCookie requestRefreshTokenCookie = createRefreshTokenCookie(refreshToken);
		ResultActions resultActions = mockMvc.perform(
				MockMvcRequestBuilders.post("/api/auth/sign-out")
						.cookie(new Cookie(requestRefreshTokenCookie.getName(), requestRefreshTokenCookie.getValue()))
		);
		//then
		verify(authService).signOut(refreshToken);
		MvcResult mvcResult = resultActions.andExpect(status().isOk()).andReturn();
		Cookie resultCookie = mvcResult.getResponse().getCookie(REFRESH_TOKEN_COOKIE_NAME);
		assertThat(resultCookie.getMaxAge()).isEqualTo(1);
	}

	private ResponseCookie createSignOutCookie() {
		return CookieUtils
				.generateResponseCookie(
						REFRESH_TOKEN_COOKIE_NAME,
						"",
						1
				);
	}

}
