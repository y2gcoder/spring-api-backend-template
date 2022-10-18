package com.y2gcoder.app.api.member.service;

import com.y2gcoder.app.api.member.service.dto.MemberInfoDto;
import com.y2gcoder.app.domain.member.constant.AuthProvider;
import com.y2gcoder.app.domain.member.constant.MemberRole;
import com.y2gcoder.app.domain.member.entity.Member;
import com.y2gcoder.app.domain.member.service.MemberService;
import com.y2gcoder.app.global.error.exception.EntityNotFoundException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;

@ExtendWith(MockitoExtension.class)
class MemberInfoServiceTest {
	@InjectMocks
	private MemberInfoService memberInfoService;

	@Mock
	private MemberService memberService;

	@Test
	@DisplayName("MemberInfoService: getMemberInfo, 성공")
	void whenGetMemberInfo_thenMemberInfo() {
		//given
		Member member = createMember();
		doReturn(member).when(memberService).findMemberById(anyLong());
		//when
		MemberInfoDto result = memberInfoService.getMemberInfo(1L);
		//then
		assertThat(result.getEmail()).isEqualTo(member.getEmail());
		assertThat(result.getNickname()).isEqualTo(member.getNickname());
	}

	@Test
	@DisplayName("MemberInfoService: getMemberInfo, memberId로 해당 멤버를 찾을 수 없음")
	void givenInvalidMemberId_whenGetMemberInfo_thenThrowEntityNotFoundException() {
		//given
		doThrow(EntityNotFoundException.class).when(memberService).findMemberById(anyLong());
		//when
		//then
		assertThatThrownBy(() -> memberInfoService.getMemberInfo(1L))
				.isInstanceOf(EntityNotFoundException.class);
	}

	private Member createMember() {
		return Member.builder()
				.email("test@test.com")
				.password("!q2w3e4r")
				.nickname("양갱")
				.profile("profile")
				.role(MemberRole.USER)
				.provider(AuthProvider.local)
				.build();
	}
}