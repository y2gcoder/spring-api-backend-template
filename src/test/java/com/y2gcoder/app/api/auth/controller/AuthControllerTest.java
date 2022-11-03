package com.y2gcoder.app.api.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.y2gcoder.app.api.auth.service.AuthService;
import com.y2gcoder.app.api.auth.service.dto.SignInDto;
import com.y2gcoder.app.api.auth.service.dto.SignUpRequest;
import com.y2gcoder.app.api.auth.service.dto.TokenRefreshDto;
import com.y2gcoder.app.domain.member.constant.MemberRole;
import com.y2gcoder.app.global.jwt.constant.GrantType;
import com.y2gcoder.app.global.jwt.dto.JwtTokenDto;
import com.y2gcoder.app.global.resolver.signinmember.SignInMemberArgumentResolver;
import com.y2gcoder.app.global.resolver.signinmember.SignInMemberDto;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.time.LocalDateTime;
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
	private SignInMemberArgumentResolver signInMemberArgumentResolver;

	private MockMvc mockMvc;
	private ObjectMapper objectMapper;

	@BeforeEach
	public void beforeEach() {
		mockMvc = MockMvcBuilders
				.standaloneSetup(authController)
				.setCustomArgumentResolvers(signInMemberArgumentResolver)
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
		assertThat(result.getAccessToken()).isEqualTo(jwtTokenDto.getAccessToken());
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
		String newAccessToken = "newAccess";
		LocalDateTime expireTime = LocalDateTime.now();
		TokenRefreshDto.Request request = createTokenRefreshRequest(refreshToken);
		TokenRefreshDto.Response tokenRefreshResponse = createTokenRefreshResponse(newAccessToken, expireTime);
		doReturn(tokenRefreshResponse).when(authService).refreshToken(any(TokenRefreshDto.Request.class));

		//when
		ResultActions resultActions = mockMvc.perform(
				MockMvcRequestBuilders.post("/api/auth/refresh")
						.contentType(MediaType.APPLICATION_JSON)
						.content(objectMapper.writeValueAsString(request))
		);

		//then
		MvcResult mvcResult = resultActions.andExpect(status().isOk()).andReturn();
		TokenRefreshDto.Response response = objectMapper
				.readValue(mvcResult.getResponse().getContentAsString(), TokenRefreshDto.Response.class);

		assertThat(response.getAccessToken()).isEqualTo(newAccessToken);
		assertThat(response.getAccessTokenExpireTime()).isEqualToIgnoringNanos(expireTime);
	}

	private TokenRefreshDto.Request createTokenRefreshRequest(String refreshToken) {
		TokenRefreshDto.Request request = new TokenRefreshDto.Request();
		request.setRefreshToken(refreshToken);
		return request;
	}

	private TokenRefreshDto.Response createTokenRefreshResponse(String accessToken, LocalDateTime expireTime) {
		return TokenRefreshDto.Response.builder()
				.grantType(GrantType.BEARER.getType())
				.accessToken(accessToken)
				.accessTokenExpireTime(expireTime)
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

	@Test
	@DisplayName("AuthController(단위): 로그아웃, 성공")
	void whenSignOut_thenSuccess() throws Exception {
		//given
		Long memberId = 1L;
		SignInMemberDto signInMemberDto = SignInMemberDto.builder()
				.memberId(memberId)
				.role(MemberRole.USER)
				.build();
		doReturn(true).when(signInMemberArgumentResolver).supportsParameter(any());
		doReturn(signInMemberDto).when(signInMemberArgumentResolver).resolveArgument(any(), any(), any(), any());

		//when
		mockMvc.perform(
				MockMvcRequestBuilders.post("/api/auth/sign-out")
		).andExpect(status().isOk());

		verify(authService).signOut(memberId);

	}

}
