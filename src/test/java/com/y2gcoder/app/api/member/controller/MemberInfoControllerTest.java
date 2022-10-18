package com.y2gcoder.app.api.member.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.y2gcoder.app.api.member.service.MemberInfoService;
import com.y2gcoder.app.api.member.service.dto.MemberInfoDto;
import com.y2gcoder.app.domain.member.constant.MemberRole;
import com.y2gcoder.app.global.resolver.signinmember.SignInMemberArgumentResolver;
import com.y2gcoder.app.global.resolver.signinmember.SignInMemberDto;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
class MemberInfoControllerTest {

	@InjectMocks
	private MemberInfoController memberInfoController;

	@Mock
	private MemberInfoService memberInfoService;

	@Mock
	private SignInMemberArgumentResolver signInMemberArgumentResolver;

	private MockMvc mockMvc;
	private ObjectMapper objectMapper;

	@BeforeEach
	public void beforeEach() {
		mockMvc = MockMvcBuilders
				.standaloneSetup(memberInfoController)
				.setCustomArgumentResolvers(signInMemberArgumentResolver)
				.build();
		objectMapper = new ObjectMapper();
	}

	@Test
	@DisplayName("MemberInfoController(단위): 내 정보 조회, 성공")
	void whenWhoAmI_thenReturnMemberInfoDto() throws Exception {
		//given
		Long memberId = 1L;
		SignInMemberDto signInMemberDto = SignInMemberDto.builder()
				.memberId(memberId)
				.role(MemberRole.USER)
				.build();
		MemberInfoDto memberInfoDto = MemberInfoDto.builder()
				.memberId(memberId)
				.email("test@test.com")
				.role(MemberRole.USER.getName())
				.build();
		doReturn(true).when(signInMemberArgumentResolver).supportsParameter(any());
		doReturn(signInMemberDto).when(signInMemberArgumentResolver).resolveArgument(any(), any(), any(), any());
		doReturn(memberInfoDto).when(memberInfoService).getMemberInfo(memberId);
		//when
		ResultActions resultActions = mockMvc.perform(
				MockMvcRequestBuilders.get("/api/members/me")
		);
		//then
		MvcResult mvcResult = resultActions.andExpect(status().isOk()).andReturn();
		MemberInfoDto result = objectMapper.readValue(mvcResult.getResponse().getContentAsString(), MemberInfoDto.class);
		assertThat(result.getMemberId()).isEqualTo(signInMemberDto.getMemberId());
		assertThat(result.getRole()).isEqualTo(signInMemberDto.getRole().getName());
	}
}