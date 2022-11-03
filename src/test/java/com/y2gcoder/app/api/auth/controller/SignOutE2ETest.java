package com.y2gcoder.app.api.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.y2gcoder.app.api.auth.service.AuthService;
import com.y2gcoder.app.api.auth.service.dto.SignInDto;
import com.y2gcoder.app.domain.member.constant.AuthProvider;
import com.y2gcoder.app.domain.member.constant.MemberRole;
import com.y2gcoder.app.domain.member.entity.Member;
import com.y2gcoder.app.domain.member.repository.MemberRepository;
import com.y2gcoder.app.domain.token.repository.RefreshTokenRepository;
import com.y2gcoder.app.global.error.ErrorResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.restdocs.AutoConfigureRestDocs;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.restdocs.RestDocumentationExtension;
import org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.payload.PayloadDocumentation.fieldWithPath;
import static org.springframework.restdocs.payload.PayloadDocumentation.responseFields;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@AutoConfigureRestDocs(uriScheme = "https", uriHost = "y2gcoder.com", uriPort = 443)
@ExtendWith(RestDocumentationExtension.class)
@AutoConfigureMockMvc
@Transactional
@SpringBootTest
class SignOutE2ETest {

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Autowired
	private MemberRepository memberRepository;

	@Autowired
	private RefreshTokenRepository refreshTokenRepository;

	@Autowired
	private AuthService authService;

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
	@DisplayName("AuthController(E2E): 로그아웃, 성공")
	void whenSignOut_thenSuccess() throws Exception {
		//given
		Member member = memberRepository.findByEmail("test@test.com").get();
		SignInDto.Response signInResponse = authService
				.signIn(createSignInRequest(member.getEmail(), "!q2w3e4r"));

		//when
		ResultActions resultActions = mockMvc.perform(
				RestDocumentationRequestBuilders.post("/api/auth/sign-out")
						.header(HttpHeaders.AUTHORIZATION, createAuthorizationHeaderValue(signInResponse))
		).andExpect(status().isOk());

		//then
		resultActions.andDo(
				document("sign-out")
		);

		assertThat(refreshTokenRepository.findByMemberId(member.getId())).isEmpty();
	}

	@Test
	@DisplayName("AuthController(E2E): 로그아웃, 액세스 토큰이 없을 때")
	void givenNotFoundAccessToken_whenSignOut_thenFail() throws Exception {
		//given
		Member member = memberRepository.findByEmail("test@test.com").get();
		authService
				.signIn(createSignInRequest(member.getEmail(), "!q2w3e4r"));

		//when
		ResultActions resultActions = mockMvc.perform(
				RestDocumentationRequestBuilders.post("/api/auth/sign-out")
		).andExpect(status().isUnauthorized());

		//then
		resultActions.andDo(
				document(
						"sign-out-fail-not-found-access-token",
						responseFields(
								fieldWithPath("errorCode").description("에러 코드"),
								fieldWithPath("errorMessage").description("에러 메시지")
						)
				)
		);

		MvcResult mvcResult = resultActions.andReturn();
		ErrorResponse errorResponse =
				objectMapper.readValue(mvcResult.getResponse().getContentAsString(), ErrorResponse.class);
		assertThat(errorResponse.getErrorCode()).isEqualTo(HttpStatus.UNAUTHORIZED.toString());
	}

	@Test
	@DisplayName("AuthController(E2E): 로그아웃, 윺효하지 않은 액세스토큰")
	void givenInvalidAccessToken_whenSignOut_thenFail() throws Exception {
		//given
		Member member = memberRepository.findByEmail("test@test.com").get();
		authService
				.signIn(createSignInRequest(member.getEmail(), "!q2w3e4r"));
		String invalidAccessToken = "invalid";

		//when
		ResultActions resultActions = mockMvc.perform(
				RestDocumentationRequestBuilders.post("/api/auth/sign-out")
						.header(HttpHeaders.AUTHORIZATION, invalidAccessToken)
		).andExpect(status().isUnauthorized());

		//then
		resultActions.andDo(
				document(
						"sign-out-fail-invalid-access-token",
						responseFields(
								fieldWithPath("errorCode").description("에러 코드"),
								fieldWithPath("errorMessage").description("에러 메시지")
						)
				)
		);

		MvcResult mvcResult = resultActions.andReturn();
		ErrorResponse errorResponse =
				objectMapper.readValue(mvcResult.getResponse().getContentAsString(), ErrorResponse.class);
		assertThat(errorResponse.getErrorCode()).isEqualTo(HttpStatus.UNAUTHORIZED.toString());

	}

	@Test
	@DisplayName("AuthController(E2E): 로그아웃, 인증 헤더에 리프레시 토큰")
	void givenRefreshToken_whenSignOut_thenFail() throws Exception {
		//given
		Member member = memberRepository.findByEmail("test@test.com").get();
		SignInDto.Response signInResponse = authService
				.signIn(createSignInRequest(member.getEmail(), "!q2w3e4r"));

		//when
		ResultActions resultActions = mockMvc.perform(
				RestDocumentationRequestBuilders.post("/api/auth/sign-out")
						.header(HttpHeaders.AUTHORIZATION, signInResponse.getGrantType() + " " + signInResponse.getRefreshToken())
		).andExpect(status().isUnauthorized());

		//then
		resultActions.andDo(
				document(
						"sign-out-fail-refresh-token",
						responseFields(
								fieldWithPath("errorCode").description("에러 코드"),
								fieldWithPath("errorMessage").description("에러 메시지")
						)
				)
		);

		MvcResult mvcResult = resultActions.andReturn();
		ErrorResponse errorResponse =
				objectMapper.readValue(mvcResult.getResponse().getContentAsString(), ErrorResponse.class);
		assertThat(errorResponse.getErrorCode()).isEqualTo(HttpStatus.UNAUTHORIZED.toString());
	}

	private SignInDto.Request createSignInRequest(String email, String password) {
		SignInDto.Request request = new SignInDto.Request();
		request.setEmail(email);
		request.setPassword(password);
		return request;
	}

	private static String createAuthorizationHeaderValue(SignInDto.Response signInResponse) {
		return signInResponse.getGrantType() + " " + signInResponse.getAccessToken();
	}

}
