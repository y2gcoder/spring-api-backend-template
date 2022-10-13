package com.y2gcoder.app.api.member.service.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

public class RefreshTokenInfo {

	@Getter @Setter
	public static class Request {
		private Long memberId;
	}

	@Getter
	public static class Response {

		private final String refreshToken;

		@JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm:ss", timezone = "Asia/Seoul")
		private final LocalDateTime refreshTokenExpireTime;

		public Response(String refreshToken, LocalDateTime refreshTokenExpireTime) {
			this.refreshToken = refreshToken;
			this.refreshTokenExpireTime = refreshTokenExpireTime;
		}
	}
}
