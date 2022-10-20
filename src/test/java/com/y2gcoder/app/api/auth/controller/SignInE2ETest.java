package com.y2gcoder.app.api.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.y2gcoder.app.api.auth.service.dto.SignInDto;
import com.y2gcoder.app.domain.member.constant.AuthProvider;
import com.y2gcoder.app.domain.member.constant.MemberRole;
import com.y2gcoder.app.domain.member.entity.Member;
import com.y2gcoder.app.domain.member.repository.MemberRepository;
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

import javax.servlet.http.Cookie;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.payload.PayloadDocumentation.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@AutoConfigureRestDocs(uriScheme = "https", uriHost = "y2gcoder.com", uriPort = 443)
@ExtendWith(RestDocumentationExtension.class)
@AutoConfigureMockMvc
@Transactional
@SpringBootTest
class SignInE2ETest {
	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private MemberRepository memberRepository;

	@Autowired
	private PasswordEncoder passwordEncoder;

	private ObjectMapper objectMapper;

	private Member savedMember;

	private static final String REFRESH_TOKEN_COOKIE_NAME = "refreshtoken";

	@BeforeEach
	public void beforeEach() {
		objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());
		savedMember = memberRepository.save(createMember());
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
	@DisplayName("AuthController(E2E): 로그인, 성공")
	void whenSignIn_thenSuccess() throws Exception {
		//given
		SignInDto.Request request = createSignInRequest();
		//when
		ResultActions resultActions = mockMvc.perform(
						RestDocumentationRequestBuilders.post("/api/auth/sign-in")
								.contentType(MediaType.APPLICATION_JSON)
								.content(objectMapper.writeValueAsString(request))
				)
				.andExpect(status().isOk());
		//then
		resultActions.andDo(
				document(
						"sign-in",
						requestFields(
								fieldWithPath("email").description("회원 이메일"),
								fieldWithPath("password")
										.description("회원 비밀번호, 최소 8자리 이상, 1개 이상의 알파벳, 숫자, 특수문자(@ $ ! % * # ? &)를 포함")
						),
						responseFields(
								fieldWithPath("grantType").description("Bearer"),
								fieldWithPath("accessToken").description("액세스 토큰"),
								fieldWithPath("accessTokenExpireTime").description("액세스 토큰 만료 시간")
						)
				)
		);

		MvcResult mvcResult = resultActions.andReturn();
		SignInDto.Response result = objectMapper
				.readValue(mvcResult.getResponse().getContentAsString(), SignInDto.Response.class);
		assertThat(result.getAccessToken()).isNotBlank();

		Member resultMember = memberRepository.findById(savedMember.getId()).get();
		assertThat(resultMember.getRefreshToken()).isNotBlank();

		Cookie resultCookie = mvcResult.getResponse().getCookie(REFRESH_TOKEN_COOKIE_NAME);
		assertThat(resultCookie).isNotNull();
	}

	@Test
	@DisplayName("AuthController(E2E): 로그인, 이메일 유효성 검사 실패")
	void givenInvalidEmail_whenSignIn_thenFail() throws Exception {
		//given
		SignInDto.Request request = createSignInRequest("invalidEmail", savedMember.getPassword());

		//when
		ResultActions resultActions = mockMvc.perform(
						RestDocumentationRequestBuilders.post("/api/auth/sign-in")
								.contentType(MediaType.APPLICATION_JSON)
								.content(objectMapper.writeValueAsString(request))
				)
				.andExpect(status().isBadRequest());
		//then
		resultActions.andDo(
				document(
						"sign-in-fail-invalid-email",
						requestFields(
								fieldWithPath("email").description("회원 이메일"),
								fieldWithPath("password")
										.description("회원 비밀번호, 최소 8자리 이상, 1개 이상의 알파벳, 숫자, 특수문자(@ $ ! % * # ? &)를 포함")
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
		assertThat(errorResponse.getErrorCode()).isEqualTo(HttpStatus.BAD_REQUEST.toString());
		assertThat(errorResponse.getErrorMessage()).contains("email");
	}

	@Test
	@DisplayName("AuthController(E2E): 로그인, 회원으로 등록한 이메일이 아님")
	void givenNotExistsMemberEmail_whenSignIn_thenFail() throws Exception {
		//given
		SignInDto.Request request = createSignInRequest("empty@empty.com", "!q2w3e4r");

		//when
		ResultActions resultActions = mockMvc.perform(
						RestDocumentationRequestBuilders.post("/api/auth/sign-in")
								.contentType(MediaType.APPLICATION_JSON)
								.content(objectMapper.writeValueAsString(request))
				)
				.andExpect(status().isBadRequest());
		//then
		resultActions.andDo(
				document(
						"sign-in-fail-not-exists-email",
						requestFields(
								fieldWithPath("email").description("회원 이메일"),
								fieldWithPath("password")
										.description("회원 비밀번호, 최소 8자리 이상, 1개 이상의 알파벳, 숫자, 특수문자(@ $ ! % * # ? &)를 포함")
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
		assertThat(errorResponse.getErrorCode()).isEqualTo(ErrorCode.NOT_FOUND_MEMBER.getErrorCode());
	}

	@Test
	@DisplayName("AuthController(E2E): 로그인, 소셜 로그인 멤버")
	void givenSocialSignInMember_whenSignIn_thenFail() throws Exception {
		//given
		Member socialMember = memberRepository.save(createSocialMember());
		SignInDto.Request request = createSignInRequest(socialMember.getEmail(), "!q2w3e4r");

		//when
		ResultActions resultActions = mockMvc.perform(
						RestDocumentationRequestBuilders.post("/api/auth/sign-in")
								.contentType(MediaType.APPLICATION_JSON)
								.content(objectMapper.writeValueAsString(request))
				)
				.andExpect(status().isUnauthorized());

		//then
		resultActions.andDo(
				document(
						"sign-in-fail-social-member",
						requestFields(
								fieldWithPath("email").description("회원 이메일"),
								fieldWithPath("password")
										.description("회원 비밀번호, 최소 8자리 이상, 1개 이상의 알파벳, 숫자, 특수문자(@ $ ! % * # ? &)를 포함")
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
		assertThat(errorResponse.getErrorCode()).isEqualTo(ErrorCode.SOCIAL_SIGN_IN_MEMBER.getErrorCode());
	}

	@Test
	@DisplayName("AuthController(E2E): 로그인, 비밀번호 불일치")
	void givenMismatchPassword_whenSignIn_Fail() throws Exception {
		//given
		SignInDto.Request request = createSignInRequest(savedMember.getEmail(), "!q@w3e4r");

		//when
		ResultActions resultActions = mockMvc.perform(
						RestDocumentationRequestBuilders.post("/api/auth/sign-in")
								.contentType(MediaType.APPLICATION_JSON)
								.content(objectMapper.writeValueAsString(request))
				)
				.andExpect(status().isBadRequest());

		//then
		resultActions.andDo(
				document(
						"sign-in-fail-mismatch-password",
						requestFields(
								fieldWithPath("email").description("회원 이메일"),
								fieldWithPath("password")
										.description("회원 비밀번호, 최소 8자리 이상, 1개 이상의 알파벳, 숫자, 특수문자(@ $ ! % * # ? &)를 포함")
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
		assertThat(errorResponse.getErrorCode()).isEqualTo(ErrorCode.MISMATCH_PASSWORD.getErrorCode());
	}

	private SignInDto.Request createSignInRequest() {
		SignInDto.Request request = new SignInDto.Request();
		request.setEmail("test@test.com");
		request.setPassword("!q2w3e4r");
		return request;
	}

	private SignInDto.Request createSignInRequest(String email, String password) {
		SignInDto.Request request = new SignInDto.Request();
		request.setEmail(email);
		request.setPassword(password);
		return request;
	}

	private Member createSocialMember() {
		return Member.builder()
				.email("social@social.com")
				.role(MemberRole.USER)
				.provider(AuthProvider.google)
				.build();
	}
}
