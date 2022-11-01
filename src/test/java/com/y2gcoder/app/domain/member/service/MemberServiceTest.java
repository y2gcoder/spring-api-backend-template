package com.y2gcoder.app.domain.member.service;

import com.y2gcoder.app.domain.member.constant.AuthProvider;
import com.y2gcoder.app.domain.member.constant.MemberRole;
import com.y2gcoder.app.domain.member.entity.Member;
import com.y2gcoder.app.domain.member.repository.MemberRepository;
import com.y2gcoder.app.global.error.exception.EntityNotFoundException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class MemberServiceTest {
	@InjectMocks
	private MemberService memberService;

	@Mock
	private MemberRepository memberRepository;

	@Test
	@DisplayName("MemberService: registerMember, 성공")
	void whenRegisterMember_thenSuccess() {
		//given
		Member member = createMember();
		doReturn(member).when(memberRepository).save(member);
		//when
		memberService.registerMember(member);
		//then
		verify(memberRepository).save(any(Member.class));
	}
	
	@Test
	@DisplayName("MemberService: findMemberById, 성공")
	void whenFindMemberById_thenGetNormalMember() {
		//given
		Member member = createMember();
		doReturn(Optional.of(member)).when(memberRepository).findById(anyLong());
		//when
		Member result = memberService.findMemberById(1L);
		//then
		assertThat(result.getEmail()).isEqualTo(member.getEmail());
		assertThat(result.getPassword()).isEqualTo(member.getPassword());
	}

	@Test
	@DisplayName("MemberService: findMemberById, 해당 ID가 없을 때 EntityNotFoundException 발생")
	void whenFindMemberByInvalidId_thenThrowEntityNotFoundException() {
		//given
		doReturn(Optional.empty()).when(memberRepository).findById(anyLong());
		//when
		//then
		assertThatThrownBy(() -> memberService.findMemberById(1L))
				.isInstanceOf(EntityNotFoundException.class);
	}

	@Test
	@DisplayName("MemberService: existsMemberByEmail, 해당 멤버 있음")
	void whenExistsMemberByEmail_thenReturnTrue() {
		//given
		String email = "test@test.com";
		doReturn(true).when(memberRepository).existsByEmail(email);
		//when
		boolean result = memberService.existsMemberByEmail(email);
		//then
		assertThat(result).isTrue();
	}

	@Test
	@DisplayName("MemberService: existsMemberByEmail, 해당 멤버 없음")
	void whenExistsMemberByEmail_thenNotFoundMemberByEmail() {
		//given
		doReturn(false).when(memberRepository).existsByEmail(anyString());
		//when
		boolean result = memberService.existsMemberByEmail("test@test.com");
		//then
		assertThat(result).isFalse();
	}

	@Test
	@DisplayName("MemberService: findMemberByEmail, 해당 멤버 있음")
	void whenFindMemberByEmail_thenFoundMember() {
		//given
		Member member = createMember();
		doReturn(Optional.of(member)).when(memberRepository).findByEmail(member.getEmail());
		//when
		Member result = memberService.findMemberByEmail(member.getEmail());
		//then
		assertThat(result.getEmail()).isEqualTo(member.getEmail());
	}

	@Test
	@DisplayName("MemberService: findMemberByEmail, 해당 멤버 없음")
	void whenFindMemberByEmail_thenNotFoundMemberByEmail() {
		//given
		doReturn(Optional.empty()).when(memberRepository).findByEmail(anyString());
		//when
		//then
		assertThatThrownBy(() -> memberService.findMemberByEmail("test@test.com"))
				.isInstanceOf(EntityNotFoundException.class);
	}

	@Test
	@DisplayName("MemberService: withdrawMember, 삭제 성공")
	void whenWithdrawMember_thenSuccess() {
		//given
		Member member = createMember();
		doReturn(Optional.of(member)).when(memberRepository).findById(anyLong());
		//when
		memberService.withdrawMember(1L);
		//then
		verify(memberRepository).delete(member);
	}

	@Test
	@DisplayName("MemberService: withdrawMember, 해당 멤버를 찾지 못함.")
	void givenInvalidMemberId_whenWithdrawMember_thenThrowEntityNotFoundException() {
		//given
		doReturn(Optional.empty()).when(memberRepository).findById(anyLong());
		//when
		//then
		assertThatThrownBy(() -> memberService.withdrawMember(1L))
				.isInstanceOf(EntityNotFoundException.class);
	}

	private Member createMember() {
		return Member.builder()
				.email("test@test.com")
				.password("!q2w3e4r")
				.role(MemberRole.USER)
				.provider(AuthProvider.local)
				.build();
	}
}
