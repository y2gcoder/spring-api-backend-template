package com.y2gcoder.app.api.member.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.y2gcoder.app.api.auth.service.AuthService;
import com.y2gcoder.app.api.auth.service.dto.SignInDto;
import com.y2gcoder.app.api.member.service.dto.MemberInfoDto;
import com.y2gcoder.app.domain.member.constant.AuthProvider;
import com.y2gcoder.app.domain.member.constant.MemberRole;
import com.y2gcoder.app.domain.member.entity.Member;
import com.y2gcoder.app.domain.member.repository.MemberRepository;
import com.y2gcoder.app.global.error.ErrorResponse;
import com.y2gcoder.app.global.jwt.dto.JwtTokenDto;
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
class WhoAmIE2ETest {

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Autowired
	private MemberRepository memberRepository;

	@Autowired
	private AuthService authService;

	private ObjectMapper objectMapper;

	private static final String EMAIL_MEMBER_1 = "member1@member.com";
	private static final String PASSWORD = "!q2w3e4r";

	private Member member1;

	@BeforeEach
	public void beforeEach() {
		objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());
		member1 = memberRepository.save(createMember(EMAIL_MEMBER_1, MemberRole.USER));
	}

	private Member createMember(String email, MemberRole role) {
		return Member.builder()
				.email(email)
				.password(passwordEncoder.encode(PASSWORD))
				.role(role)
				.provider(AuthProvider.local)
				.build();
	}

	@Test
	@DisplayName("MemberInfoController(E2E): 내 정보 조회, 성공")
	void whenWhoAmI_thenSuccess() throws Exception {
		//given
		JwtTokenDto jwtTokenDto = authService.signIn(createSignInRequest(member1.getEmail(), PASSWORD));

		//when
		ResultActions resultActions = mockMvc.perform(
				RestDocumentationRequestBuilders.get("/api/members/me")
						.header(HttpHeaders.AUTHORIZATION, createAuthorizationHeaderValue(jwtTokenDto))
		).andExpect(status().isOk());

		//then
		resultActions.andDo(
				document(
						"who-am-I",
						responseFields(
								fieldWithPath("memberId").description("회원 ID"),
								fieldWithPath("email").description("회원 이메일"),
								fieldWithPath("nickname").description("회원 닉네임"),
								fieldWithPath("profile").description("회원 프로필 이미지"),
								fieldWithPath("role").description("회원 권한")
						)
				)
		);

		MvcResult mvcResult = resultActions.andReturn();
		MemberInfoDto response = objectMapper.readValue(mvcResult.getResponse().getContentAsString(), MemberInfoDto.class);
		assertThat(response.getMemberId()).isEqualTo(member1.getId());
		assertThat(response.getEmail()).isEqualTo(member1.getEmail());

	}

	@Test
	@DisplayName("MemberInfoController(E2E): 내 정보 조회, 액세스 토큰이 없음")
	void givenNotFoundAccessToken_whenWhoAmI_thenFail() throws Exception {
		//given
		//when
		ResultActions resultActions = mockMvc.perform(
				RestDocumentationRequestBuilders.get("/api/members/me")
		).andExpect(status().isUnauthorized());

		//then
		resultActions.andDo(
				document(
						"who-am-I-fail-not-found-access-token",
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
	@DisplayName("MemberInfoController(E2E): 내 정보 조회, 유효하지 않은 액세스 토큰")
	void givenInvalidAccessToken_whenWhoAmI_thenFail() throws Exception {
		//given
		String invalidAccessToken = "Bearer invalid";

		//when
		ResultActions resultActions = mockMvc.perform(
				RestDocumentationRequestBuilders.get("/api/members/me")
						.header(HttpHeaders.AUTHORIZATION, invalidAccessToken)
		).andExpect(status().isUnauthorized());

		//then
		resultActions.andDo(
				document(
						"who-am-I-fail-invalid-access-token",
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

	private static String createAuthorizationHeaderValue(JwtTokenDto jwtTokenDto) {
		return jwtTokenDto.getGrantType() + " " + jwtTokenDto.getAccessToken();
	}
}
