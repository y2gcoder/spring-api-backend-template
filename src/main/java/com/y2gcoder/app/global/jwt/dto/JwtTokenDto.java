package com.y2gcoder.app.global.jwt.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.y2gcoder.app.global.util.DateTimeUtils;
import lombok.*;

import java.time.LocalDateTime;
import java.util.Date;

@Getter
@Setter
@NoArgsConstructor
public class JwtTokenDto {
	private String grantType;
	private String accessToken;
	@JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm:ss", timezone = "Asia/Seoul")
	private LocalDateTime accessTokenExpireTime;
	private String refreshToken;
	@JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm:ss", timezone = "Asia/Seoul")
	private LocalDateTime refreshTokenExpireTime;

	@Builder
	public JwtTokenDto(String grantType, String accessToken, Date accessTokenExpireTime, String refreshToken, Date refreshTokenExpireTime) {
		this.grantType = grantType;
		this.accessToken = accessToken;
		this.accessTokenExpireTime = DateTimeUtils.convertToLocalDateTime(accessTokenExpireTime);
		this.refreshToken = refreshToken;
		this.refreshTokenExpireTime = DateTimeUtils.convertToLocalDateTime(refreshTokenExpireTime);
	}
}
