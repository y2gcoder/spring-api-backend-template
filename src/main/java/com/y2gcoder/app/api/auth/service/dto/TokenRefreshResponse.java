package com.y2gcoder.app.api.auth.service.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.*;

import java.time.LocalDateTime;

@Getter
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class TokenRefreshResponse {
	private String grantType;

	private String accessToken;

	@JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm:ss", timezone = "Asia/Seoul")
	private LocalDateTime accessTokenExpireTime;

	@Builder
	public TokenRefreshResponse(String grantType, String accessToken, LocalDateTime accessTokenExpireTime) {
		this.grantType = grantType;
		this.accessToken = accessToken;
		this.accessTokenExpireTime = accessTokenExpireTime;
	}
}
