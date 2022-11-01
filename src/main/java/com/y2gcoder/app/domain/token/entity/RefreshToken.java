package com.y2gcoder.app.domain.token.entity;

import com.y2gcoder.app.domain.common.BaseTimeEntity;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import java.time.LocalDateTime;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
public class RefreshToken extends BaseTimeEntity {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	private Long memberId;

	private String refreshToken;

	private LocalDateTime tokenExpirationTime;

	@Builder
	public RefreshToken(Long memberId, String refreshToken, LocalDateTime tokenExpirationTime) {
		this.memberId = memberId;
		this.refreshToken = refreshToken;
		this.tokenExpirationTime = tokenExpirationTime;
	}

	public void updateRefreshToken(String refreshToken, LocalDateTime tokenExpirationTime) {
		this.refreshToken = refreshToken;
		this.tokenExpirationTime = tokenExpirationTime;
	}
}
