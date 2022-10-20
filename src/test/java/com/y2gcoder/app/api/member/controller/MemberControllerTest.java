package com.y2gcoder.app.api.member.controller;

import com.y2gcoder.app.domain.member.constant.MemberRole;
import com.y2gcoder.app.domain.member.service.MemberService;
import com.y2gcoder.app.global.resolver.signinmember.SignInMemberArgumentResolver;
import com.y2gcoder.app.global.resolver.signinmember.SignInMemberDto;
import com.y2gcoder.app.global.util.CookieUtils;
import com.y2gcoder.app.global.util.RefreshTokenCookieUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseCookie;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import javax.servlet.http.Cookie;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
class MemberControllerTest {

	@InjectMocks
	private MemberController memberController;

	@Mock
	private SignInMemberArgumentResolver signInMemberArgumentResolver;

	@Mock
	private MemberService memberService;

	@Mock
	private RefreshTokenCookieUtils refreshTokenCookieUtils;

	private MockMvc mockMvc;

	private static final String REFRESH_TOKEN_COOKIE_NAME = "refreshtoken";

	@BeforeEach
	public void beforeEach() {
		mockMvc = MockMvcBuilders
				.standaloneSetup(memberController)
				.setCustomArgumentResolvers(signInMemberArgumentResolver)
				.build();
	}

	@Test
	@DisplayName("MemberController(단위): 회원탈퇴, 관리자가 삭제함.")
	void whenWithdrawMemberByAdmin_thenWithdrawMember() throws Exception {
		//given
		Long adminId = 1L;
		SignInMemberDto signInMemberDto = createAdminSignInMemberDto(adminId);
		doReturn(true).when(signInMemberArgumentResolver).supportsParameter(any());
		doReturn(signInMemberDto).when(signInMemberArgumentResolver).resolveArgument(any(), any(), any(), any());
		Long targetMemberId = 2L;

		//when
		ResultActions resultActions = mockMvc.perform(
				MockMvcRequestBuilders.delete("/api/members/{id}", targetMemberId)
		);
		//then
		verify(memberService, times(1)).withdrawMember(targetMemberId);
		MvcResult mvcResult = resultActions.andExpect(status().isOk()).andReturn();
		Cookie[] cookies = mvcResult.getResponse().getCookies();
		assertThat(cookies).isEmpty();
	}

	private SignInMemberDto createAdminSignInMemberDto(Long adminId) {
		return SignInMemberDto.builder()
				.memberId(adminId)
				.role(MemberRole.ADMIN)
				.build();
	}

	@Test
	@DisplayName("MemberController(단위): 회원탈퇴, 자기 자신이 삭제")
	void whenWithdrawMemberByMyself_thenWithdrawMyselfAndDeleteCookie() throws Exception {
		//given
		Long memberId = 1L;
		SignInMemberDto signInMemberDto = createSignInMemberDto(memberId);
		doReturn(true).when(signInMemberArgumentResolver).supportsParameter(any());
		doReturn(signInMemberDto).when(signInMemberArgumentResolver).resolveArgument(any(), any(), any(), any());
		ResponseCookie signOutCookie = createSignOutCookie();
		doReturn(signOutCookie).when(refreshTokenCookieUtils).generateSignOutCookie();
		//when
		ResultActions resultActions = mockMvc.perform(
				MockMvcRequestBuilders.delete("/api/members/{id}", memberId)
		);
		//then
		verify(memberService, times(1)).withdrawMember(memberId);
		MvcResult mvcResult = resultActions.andExpect(status().isOk()).andReturn();
		Cookie resultCookie = mvcResult.getResponse().getCookie(REFRESH_TOKEN_COOKIE_NAME);
		assertThat(resultCookie.getMaxAge()).isEqualTo(1);
	}

	private SignInMemberDto createSignInMemberDto(Long memberId) {
		return SignInMemberDto.builder()
				.memberId(memberId)
				.role(MemberRole.USER)
				.build();
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
