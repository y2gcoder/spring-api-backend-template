package com.y2gcoder.app.api.member.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.y2gcoder.app.api.auth.service.AuthService;
import com.y2gcoder.app.api.auth.service.dto.SignInDto;
import com.y2gcoder.app.domain.member.constant.AuthProvider;
import com.y2gcoder.app.domain.member.constant.MemberRole;
import com.y2gcoder.app.domain.member.entity.Member;
import com.y2gcoder.app.domain.member.repository.MemberRepository;
import com.y2gcoder.app.global.error.ErrorCode;
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

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.payload.PayloadDocumentation.fieldWithPath;
import static org.springframework.restdocs.payload.PayloadDocumentation.responseFields;
import static org.springframework.restdocs.request.RequestDocumentation.parameterWithName;
import static org.springframework.restdocs.request.RequestDocumentation.pathParameters;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@AutoConfigureRestDocs(uriScheme = "https", uriHost = "y2gcoder.com", uriPort = 443)
@ExtendWith(RestDocumentationExtension.class)
@AutoConfigureMockMvc
@Transactional
@SpringBootTest
class WithdrawMemberE2ETest {

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
	private static final String EMAIL_MEMBER_2 = "member2@member.com";
	private static final String EMAIL_ADMIN = "admin@member.com";
	private static final String PASSWORD = "!q2w3e4r";

	private Member member1;
	private Member member2;
	private Member admin;

	@BeforeEach
	public void beforeEach() {
		objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());
		member1 = memberRepository.save(createMember(EMAIL_MEMBER_1, MemberRole.USER));
		member2 = memberRepository.save(createMember(EMAIL_MEMBER_2, MemberRole.USER));
		admin = memberRepository.save(createMember(EMAIL_ADMIN, MemberRole.ADMIN));
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
	@DisplayName("MemberController(E2E): 회원 탈퇴, 자기 자신이 회원 탈퇴!")
	void givenMember1_whenWithdrawMember1_thenSuccess() throws Exception {
		//given
		JwtTokenDto jwtTokenDto = authService.signIn(createSignInRequest(member1.getEmail(), PASSWORD));

		//when
		ResultActions resultActions = mockMvc.perform(
				RestDocumentationRequestBuilders.delete("/api/members/{id}", member1.getId())
						.header(HttpHeaders.AUTHORIZATION, createAuthorizationHeaderValue(jwtTokenDto))
		).andExpect(status().isOk());

		//then
		resultActions.andDo(
				document(
						"withdraw-member",
						pathParameters(
								parameterWithName("id").description("Member Id")
						)
				)
		);

		List<Member> result = memberRepository.findAll();
		assertThat(result.size()).isEqualTo(2);
		assertThat(memberRepository.findById(member1.getId()).isEmpty()).isTrue();

	}

	@Test
	@DisplayName("MemberController(E2E): 회원 탈퇴, 관리자가 일반 사용자 탈퇴")
	void givenAdminMember_whenWithdrawMember1_thenSuccess() throws Exception {
		//given
		JwtTokenDto jwtTokenDto = authService.signIn(createSignInRequest(admin.getEmail(), PASSWORD));

		//when
		ResultActions resultActions = mockMvc.perform(
				RestDocumentationRequestBuilders.delete("/api/members/{id}", member1.getId())
						.header(HttpHeaders.AUTHORIZATION, createAuthorizationHeaderValue(jwtTokenDto))
		).andExpect(status().isOk());

		//then
		resultActions.andDo(
				document(
						"withdraw-member-by-admin",
						pathParameters(
								parameterWithName("id").description("Member Id")
						)
				)
		);

		List<Member> result = memberRepository.findAll();
		assertThat(result.size()).isEqualTo(2);
		assertThat(memberRepository.findById(member1.getId()).isEmpty()).isTrue();
	}

	@Test
	@DisplayName("MemberController(E2E): 회원 탈퇴, 액세스 토큰이 없음")
	void givenNotFoundAccessToken_whenWithdrawMember_thenFail() throws Exception {
		//given
		//when
		ResultActions resultActions = mockMvc.perform(
				RestDocumentationRequestBuilders.delete("/api/members/{id}", member1.getId())
		).andExpect(status().isUnauthorized());

		//then
		resultActions.andDo(
				document(
						"withdraw-member-fail-not-found-access-token",
						pathParameters(
								parameterWithName("id").description("Member Id")
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
		assertThat(errorResponse.getErrorCode()).isEqualTo(HttpStatus.UNAUTHORIZED.toString());
	}

	@Test
	@DisplayName("MemberController(E2E): 회원 탈퇴, 유효하지 않은 액세스 토큰")
	void givenInvalidAccessToken_whenWithdrawMember_thenFail() throws Exception {
		//given
		String invalidAccessToken = "Bearer invalid";

		//when
		ResultActions resultActions = mockMvc.perform(
				RestDocumentationRequestBuilders.delete("/api/members/{id}", member1.getId())
						.header(HttpHeaders.AUTHORIZATION, invalidAccessToken)
		).andExpect(status().isUnauthorized());

		//then
		resultActions.andDo(
				document(
						"withdraw-member-fail-invalid-access-token",
						pathParameters(
								parameterWithName("id").description("Member Id")
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
		assertThat(errorResponse.getErrorCode()).isEqualTo(HttpStatus.UNAUTHORIZED.toString());
	}

	@Test
	@DisplayName("MemberController(E2E): 회원 탈퇴, 리프레시 토큰으로 탈퇴 시도")
	void givenRefreshToken_whenWhoAmI_thenFail() throws Exception {
		//given
		JwtTokenDto jwtTokenDto = authService.signIn(createSignInRequest(member1.getEmail(), PASSWORD));

		//when
		ResultActions resultActions = mockMvc.perform(
				RestDocumentationRequestBuilders.delete("/api/members/{id}", member1.getId())
						.header(HttpHeaders.AUTHORIZATION, jwtTokenDto.getGrantType() + " " + jwtTokenDto.getRefreshToken())
		).andExpect(status().isUnauthorized());

		//then
		resultActions.andDo(
				document(
						"withdraw-member-fail-refresh-token",
						pathParameters(
								parameterWithName("id").description("Member Id")
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
		assertThat(errorResponse.getErrorCode()).isEqualTo(HttpStatus.UNAUTHORIZED.toString());
	}

	@Test
	@DisplayName("MemberController(E2E): 회원 탈퇴, 일반 사용자가 다른 사용자를 탈퇴하려고 시도")
	void givenMember2_whenWithdrawMember1_thenFail() throws Exception {
		JwtTokenDto jwtTokenDto = authService.signIn(createSignInRequest(member2.getEmail(), PASSWORD));

		//when
		ResultActions resultActions = mockMvc.perform(
				RestDocumentationRequestBuilders.delete("/api/members/{id}", member1.getId())
						.header(HttpHeaders.AUTHORIZATION, createAuthorizationHeaderValue(jwtTokenDto))
		).andExpect(status().isForbidden());

		//then
		resultActions.andDo(
				document(
						"withdraw-member-fail-another-normal-member",
						pathParameters(
								parameterWithName("id").description("Member Id")
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
		assertThat(errorResponse.getErrorCode()).isEqualTo(HttpStatus.FORBIDDEN.toString());
	}

	@Test
	@DisplayName("MemberController(E2E): 회원 탈퇴, 없는 회원 탈퇴 시도")
	void givenWrongMemberId_whenWithdrawMemberByAdmin_thenFail() throws Exception {
		//given
		JwtTokenDto jwtTokenDto = authService.signIn(createSignInRequest(admin.getEmail(), PASSWORD));

		//when
		ResultActions resultActions = mockMvc.perform(
				RestDocumentationRequestBuilders.delete("/api/members/{id}", 4L)
						.header(HttpHeaders.AUTHORIZATION, createAuthorizationHeaderValue(jwtTokenDto))
		).andExpect(status().isBadRequest());

		//then
		resultActions.andDo(
				document(
						"withdraw-member-fail-not-found-target",
						pathParameters(
								parameterWithName("id").description("Member Id")
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
