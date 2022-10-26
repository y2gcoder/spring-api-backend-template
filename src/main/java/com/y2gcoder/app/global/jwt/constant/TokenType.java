package com.y2gcoder.app.global.jwt.constant;

public enum TokenType {
	access, refresh;

	public static boolean isAccessToken(String tokenType) {
		return TokenType.access.name().equals(tokenType);
	}

	public static boolean isRefreshToken(String tokenType) {
		return TokenType.refresh.name().equals(tokenType);
	}
}
