package com.y2gcoder.app.api.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.y2gcoder.app.api.auth.service.AuthService;
import com.y2gcoder.app.api.auth.service.dto.SignInDto;
import com.y2gcoder.app.api.auth.service.dto.TokenRefreshDto;
import com.y2gcoder.app.domain.member.constant.AuthProvider;
import com.y2gcoder.app.domain.member.constant.MemberRole;
import com.y2gcoder.app.domain.member.entity.Member;
import com.y2gcoder.app.domain.member.repository.MemberRepository;
import com.y2gcoder.app.domain.token.service.TokenService;
import com.y2gcoder.app.global.error.ErrorCode;
import com.y2gcoder.app.global.error.ErrorResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.restdocs.AutoConfigureRestDocs;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.restdocs.RestDocumentationExtension;
import org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.payload.PayloadDocumentation.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@AutoConfigureRestDocs(uriScheme = "https", uriHost = "y2gcoder.com", uriPort = 443)
@ExtendWith(RestDocumentationExtension.class)
@AutoConfigureMockMvc
@Transactional
@SpringBootTest
class TokenRefreshE2ETest {

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Autowired
	private MemberRepository memberRepository;

	@Autowired
	private AuthService authService;

	@Autowired
	private TokenService tokenService;

	private ObjectMapper objectMapper;

	@BeforeEach
	public void beforeEach() {
		objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());
		memberRepository.save(createMember());
	}

	private Member createMember() {
		return Member.builder()
				.email("test@test.com")
				.password(passwordEncoder.encode("!q2w3e4r"))
				.role(MemberRole.USER)
				.provider(AuthProvider.local)
				.build();
	}

	@Test
	@DisplayName("AuthController(E2E): 토큰 리프레시, 성공")
	void whenRefreshToken_thenSuccess() throws Exception {
		//given
		Member member = memberRepository.findByEmail("test@test.com").get();
		SignInDto.Response signInResponse = authService
				.signIn(createSignInRequest(member.getEmail(), "!q2w3e4r"));
		String originalRefreshToken = signInResponse.getRefreshToken();
		TokenRefreshDto.Request request = createTokenRefreshRequest(originalRefreshToken);

		//when
		ResultActions resultActions = mockMvc.perform(
			RestDocumentationRequestBuilders.post("/api/auth/refresh")
					.contentType(MediaType.APPLICATION_JSON)
					.content(objectMapper.writeValueAsString(request))
		).andExpect(status().isOk());

		//빠른 시간 안에 토큰을 재생성하면 똑같은 토큰이 나옴.

		//then
		resultActions.andDo(
				document(
						"token-refresh",
						requestFields(
								fieldWithPath("refreshToken").description("리프레시 토큰")
						),
						responseFields(
								fieldWithPath("grantType").description("Bearer"),
								fieldWithPath("accessToken").description("액세스 토큰"),
								fieldWithPath("accessTokenExpireTime").description("액세스 토큰 만료 시간")
						)
				)
		);


		MvcResult mvcResult = resultActions.andReturn();
		TokenRefreshDto.Response response = objectMapper
				.readValue(mvcResult.getResponse().getContentAsString(), TokenRefreshDto.Response.class);
		assertThat(response.getAccessToken()).isNotBlank();
	}

	private TokenRefreshDto.Request createTokenRefreshRequest(String refreshToken) {
		TokenRefreshDto.Request request = new TokenRefreshDto.Request();
		request.setRefreshToken(refreshToken);
		return request;
	}

	@Test
	@DisplayName("AuthController(E2E): 토큰 리프레시, 요청 JSON이 없음.")
	void givenNotExistsRefreshTokenCookie_whenRefreshToken_thenFail() throws Exception {
		//given
		//when
		ResultActions resultActions = mockMvc.perform(
				RestDocumentationRequestBuilders.post("/api/auth/refresh")
		).andExpect(status().isBadRequest());

		//then
		resultActions.andDo(
				document(
						"token-refresh-fail-not-exists-request",
						responseFields(
								fieldWithPath("errorCode").description("에러 코드"),
								fieldWithPath("errorMessage").description("에러 메시지")
						)
				)
		);

		MvcResult mvcResult = resultActions.andReturn();
		ErrorResponse errorResponse =
				objectMapper.readValue(mvcResult.getResponse().getContentAsString(), ErrorResponse.class);
		assertThat(errorResponse.getErrorCode()).isEqualTo(HttpStatus.BAD_REQUEST.toString());

	}

	@Test
	@DisplayName("AuthController(E2E): 토큰 리프레시, 토큰 유효성 검사 실패")
	void givenInvalidRefreshToken_whenRefreshToken_thenFail() throws Exception {
		//given
		TokenRefreshDto.Request request = createTokenRefreshRequest("invalidRefreshToken");
		//when
		ResultActions resultActions = mockMvc.perform(
				RestDocumentationRequestBuilders.post("/api/auth/refresh")
						.contentType(MediaType.APPLICATION_JSON)
						.content(objectMapper.writeValueAsString(request))
		).andExpect(status().isUnauthorized());

		//then
		resultActions.andDo(
				document(
						"token-refresh-fail-invalid-refresh-token",
						requestFields(
								fieldWithPath("refreshToken").description("리프레시 토큰")
						),
						responseFields(
								fieldWithPath("errorCode").description("에러 코드"),
								fieldWithPath("errorMessage").description("에러 메시지")
						)
				)
		);

		MvcResult mvcResult = resultActions.andReturn();
		ErrorResponse errorResponse =
				objectMapper.readValue(mvcResult.getResponse().getContentAsString(), ErrorResponse.class);
		assertThat(errorResponse.getErrorCode()).isEqualTo(ErrorCode.INVALID_REFRESH_TOKEN.getErrorCode());
	}

	@Test
	@DisplayName("AuthController(E2E): 토큰 리프레시, 액세스 토큰을 넣음.")
	void givenRequestAccessToken_whenRefreshToken_thenFail() throws Exception {
		//given
		Member member = memberRepository.findByEmail("test@test.com").get();
		SignInDto.Response signInResponse = authService
				.signIn(createSignInRequest(member.getEmail(), "!q2w3e4r"));
		String accessToken = signInResponse.getAccessToken();
		TokenRefreshDto.Request request = createTokenRefreshRequest(accessToken);

		//when
		ResultActions resultActions = mockMvc.perform(
				RestDocumentationRequestBuilders.post("/api/auth/refresh")
						.contentType(MediaType.APPLICATION_JSON)
						.content(objectMapper.writeValueAsString(request))
		).andExpect(status().isUnauthorized());

		//then
		resultActions.andDo(
				document(
						"token-refresh-fail-by-access-token",
						requestFields(
								fieldWithPath("refreshToken").description("리프레시 토큰")
						),
						responseFields(
								fieldWithPath("errorCode").description("에러 코드"),
								fieldWithPath("errorMessage").description("에러 메시지")
						)
				)
		);

		MvcResult mvcResult = resultActions.andReturn();
		ErrorResponse errorResponse =
				objectMapper.readValue(mvcResult.getResponse().getContentAsString(), ErrorResponse.class);
		assertThat(errorResponse.getErrorCode()).isEqualTo(ErrorCode.INVALID_REFRESH_TOKEN.getErrorCode());
	}

	@Test
	@DisplayName("AuthController(E2E): 토큰 리프레시, 해당 리프레시 토큰 없음.")
	void givenNotFoundMemberByRefreshToken_whenRefreshToken_thenFail() throws Exception {
		//given
		Member member = memberRepository.findByEmail("test@test.com").get();
		SignInDto.Response signInResponse = authService
				.signIn(createSignInRequest(member.getEmail(), "!q2w3e4r"));
		String originalRefreshToken = signInResponse.getRefreshToken();
		TokenRefreshDto.Request request = createTokenRefreshRequest(originalRefreshToken);
		tokenService.removeRefreshToken(member.getId());

		//when
		ResultActions resultActions = mockMvc.perform(
				RestDocumentationRequestBuilders.post("/api/auth/refresh")
						.contentType(MediaType.APPLICATION_JSON)
						.content(objectMapper.writeValueAsString(request))
		).andExpect(status().isUnauthorized());

		//then
		resultActions.andDo(
				document(
						"token-refresh-fail-not-found-refresh-token",
						requestFields(
								fieldWithPath("refreshToken").description("리프레시 토큰")
						),
						responseFields(
								fieldWithPath("errorCode").description("에러 코드"),
								fieldWithPath("errorMessage").description("에러 메시지")
						)
				)
		);

		MvcResult mvcResult = resultActions.andReturn();
		ErrorResponse errorResponse =
				objectMapper.readValue(mvcResult.getResponse().getContentAsString(), ErrorResponse.class);
		assertThat(errorResponse.getErrorCode()).isEqualTo(ErrorCode.NOT_FOUND_REFRESH_TOKEN.getErrorCode());
	}

	@Test
	@DisplayName("AuthController(E2E): 토큰 리프레시, 리프레시 토큰이 만료됨.")
	void givenNotFoundMemberByExpiredRefreshTokenFromDB_whenRefreshToken_thenFail() throws Exception {
		//given
		Member member = memberRepository.findByEmail("test@test.com").get();
		SignInDto.Response signInResponse = authService
				.signIn(createSignInRequest(member.getEmail(), "!q2w3e4r"));
		String originalRefreshToken = signInResponse.getRefreshToken();
		TokenRefreshDto.Request request = createTokenRefreshRequest(originalRefreshToken);
		tokenService.updateRefreshToken(member.getId(), originalRefreshToken, LocalDateTime.now().minusSeconds(1));

		//when
		ResultActions resultActions = mockMvc.perform(
				RestDocumentationRequestBuilders.post("/api/auth/refresh")
						.contentType(MediaType.APPLICATION_JSON)
						.content(objectMapper.writeValueAsString(request))
		).andExpect(status().isUnauthorized());

		//then
		resultActions.andDo(
				document(
						"token-refresh-fail-expired-refresh-token-from-db",
						requestFields(
								fieldWithPath("refreshToken").description("리프레시 토큰")
						),
						responseFields(
								fieldWithPath("errorCode").description("에러 코드"),
								fieldWithPath("errorMessage").description("에러 메시지")
						)
				)
		);

		MvcResult mvcResult = resultActions.andReturn();
		ErrorResponse errorResponse =
				objectMapper.readValue(mvcResult.getResponse().getContentAsString(), ErrorResponse.class);
		assertThat(errorResponse.getErrorCode()).isEqualTo(ErrorCode.EXPIRED_REFRESH_TOKEN.getErrorCode());
	}

	private SignInDto.Request createSignInRequest(String email, String password) {
		SignInDto.Request request = new SignInDto.Request();
		request.setEmail(email);
		request.setPassword(password);
		return request;
	}

}
