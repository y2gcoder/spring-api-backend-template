package com.y2gcoder.app.domain.member.entity;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;

class MemberTest {

	@Test
	@DisplayName("Entity Member: updateRefreshToken, 성공")
	void updateRefreshToken_Normal_Success() {
		//given
		Member member = Member.builder()
				.email("test@test.com")
				.build();
		//when
		String refreshToken = "refreshToken";
		LocalDateTime testTime = LocalDateTime.of(2022, 10, 16, 23, 59, 59);
		member.updateRefreshToken(refreshToken, testTime);
		//then
		assertThat(member.getRefreshToken()).isEqualTo(refreshToken);
		assertThat(member.getTokenExpirationTime()).isEqualTo(testTime);
	}
}