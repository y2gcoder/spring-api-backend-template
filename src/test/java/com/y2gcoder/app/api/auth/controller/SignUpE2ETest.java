package com.y2gcoder.app.api.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.y2gcoder.app.api.auth.service.dto.SignUpRequest;
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
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.payload.PayloadDocumentation.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@AutoConfigureRestDocs(uriScheme = "https", uriHost = "y2gcoder.com", uriPort = 443)
@ExtendWith(RestDocumentationExtension.class)
@AutoConfigureMockMvc
@Transactional
@SpringBootTest
class SignUpE2ETest {

	@Autowired
	private MockMvc mockMvc;

	private ObjectMapper objectMapper;

	@Autowired
	private MemberRepository memberRepository;

	@BeforeEach
	public void beforeEach() {
		objectMapper = new ObjectMapper();
	}

	@Test
	@DisplayName("AuthController(E2E): 회원가입, 성공")
	void whenSignUp_thenSuccess() throws Exception {
		//given
		SignUpRequest request = createSignUpRequest();
		//when
		ResultActions resultActions = mockMvc.perform(
				RestDocumentationRequestBuilders.post("/api/auth/sign-up")
						.contentType(MediaType.APPLICATION_JSON)
						.content(objectMapper.writeValueAsString(request))
		);
		//then
		resultActions.andExpect(status().isCreated())
				.andDo(document("sign-up", requestFields(
						fieldWithPath("email").description("회원 이메일"),
						fieldWithPath("password")
								.description("회원 비밀번호, 최소 8자리 이상, 1개 이상의 알파벳, 숫자, 특수문자(@ $ ! % * # ? &)를 포함")
				)));

		Member result = memberRepository.findByEmail(request.getEmail()).get();
		assertThat(result.getEmail()).isEqualTo(request.getEmail());
		assertThat(result.getPassword()).isNotEmpty();
	}

	private SignUpRequest createSignUpRequest() {
		SignUpRequest result = new SignUpRequest();
		result.setEmail("test@test.com");
		result.setPassword("!q2w3e4r");
		return result;
	}

	@Test
	@DisplayName("AuthController(E2E): 회원가입, 이메일 유효성 검사 실패")
	void givenInvalidEmail_whenSignUp_thenFail() throws Exception {
		//given
		SignUpRequest request = createSignUpRequest("invalidEmail", "!q2w3e4r");
		//when
		ResultActions resultActions = mockMvc.perform(
				RestDocumentationRequestBuilders.post("/api/auth/sign-up")
						.contentType(MediaType.APPLICATION_JSON)
						.content(objectMapper.writeValueAsString(request))
		).andExpect(status().isBadRequest());

		//then

		resultActions.andDo(
				document(
						"sign-up-fail-invalid-email",
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
	@DisplayName("AuthController(E2E): 회원가입, 비밀번호 유효성 검사 실패")
	void givenInvalidPassword_whenSignUp_thenFail() throws Exception {
		//given
		SignUpRequest request = createSignUpRequest("test@test.com", "12345");
		//when
		ResultActions resultActions = mockMvc.perform(
				RestDocumentationRequestBuilders.post("/api/auth/sign-up")
						.contentType(MediaType.APPLICATION_JSON)
						.content(objectMapper.writeValueAsString(request))
		).andExpect(status().isBadRequest());

		//then

		resultActions.andDo(
				document(
						"sign-up-fail-invalid-password",
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
		assertThat(errorResponse.getErrorMessage()).contains("password");
	}

	@Test
	@DisplayName("AuthController(E2E): 회원가입, 중복 이메일")
	void givenAlreadyEmailExists_whenSignUp_ThenFail() throws Exception {
		//given
		String email = "test@test.com";
		Member member = Member.builder()
				.email(email)
				.password("!q2w3e4r")
				.role(MemberRole.USER)
				.provider(AuthProvider.local)
				.build();
		memberRepository.save(member);

		SignUpRequest request = createSignUpRequest(email, "!q2w3e4r");
		//when
		ResultActions resultActions = mockMvc.perform(
				RestDocumentationRequestBuilders.post("/api/auth/sign-up")
						.contentType(MediaType.APPLICATION_JSON)
						.content(objectMapper.writeValueAsString(request))
		).andExpect(status().isBadRequest());

		//then
		resultActions.andDo(
				document(
						"sign-up-fail-already-email-exists",
						responseFields(
								fieldWithPath("errorCode").description("에러 코드"),
								fieldWithPath("errorMessage").description("에러 메시지")
						)
				)
		);

		MvcResult mvcResult = resultActions.andReturn();
		ErrorResponse errorResponse =
				objectMapper.readValue(mvcResult.getResponse().getContentAsString(), ErrorResponse.class);
		assertThat(errorResponse.getErrorCode()).isEqualTo(ErrorCode.ALREADY_REGISTERED_MEMBER.getErrorCode());
	}

	private SignUpRequest createSignUpRequest(String email, String password) {
		SignUpRequest result = new SignUpRequest();
		result.setEmail(email);
		result.setPassword(password);
		return result;
	}
}
