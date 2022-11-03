package com.y2gcoder.app.api.member.controller;

import com.y2gcoder.app.domain.member.service.MemberService;
import com.y2gcoder.app.global.resolver.signinmember.SignInMemberArgumentResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
class MemberControllerTest {

	@InjectMocks
	private MemberController memberController;

	@Mock
	private SignInMemberArgumentResolver signInMemberArgumentResolver;

	@Mock
	private MemberService memberService;

	private MockMvc mockMvc;

	@BeforeEach
	public void beforeEach() {
		mockMvc = MockMvcBuilders
				.standaloneSetup(memberController)
				.setCustomArgumentResolvers(signInMemberArgumentResolver)
				.build();
	}

	@Test
	@DisplayName("MemberController(단위): 회원탈퇴, 성공")
	void whenWithdrawMemberByMyself_thenWithdrawMyselfAndDeleteCookie() throws Exception {
		//given
		Long memberId = 1L;

		//when
		mockMvc.perform(
				MockMvcRequestBuilders.delete("/api/members/{id}", memberId)
		).andExpect(status().isOk());
		//then
		verify(memberService, times(1)).withdrawMember(memberId);
	}

}
