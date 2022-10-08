package com.y2gcoder.app.domain.member.entity;

import com.y2gcoder.app.domain.common.BaseTimeEntity;
import com.y2gcoder.app.domain.member.constant.AuthProvider;
import com.y2gcoder.app.domain.member.constant.MemberRole;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.time.LocalDateTime;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
public class Member extends BaseTimeEntity {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@Column(unique = true, length = 50, nullable = false)
	private String email;

	@Column(length = 200)
	private String password;

	private String nickname;

	private String profile;

	@Enumerated(EnumType.STRING)
	@Column(nullable = false, length = 10)
	private MemberRole role;

	@Enumerated(EnumType.STRING)
	@Column(nullable = false, length = 10)
	private AuthProvider provider;

	private String refreshToken;

	private LocalDateTime tokenExpirationTime;

	@Builder
	public Member(
			String email, String password, String nickname, String profile, MemberRole role, AuthProvider provider
	) {
		this.email = email;
		this.password = password;
		this.nickname = nickname;
		this.profile = profile;
		this.role = role;
		this.provider = provider;
	}

	public void updateRefreshToken(String refreshToken, LocalDateTime tokenExpirationTime) {
		this.refreshToken = refreshToken;
		this.tokenExpirationTime = tokenExpirationTime;
	}
}
