package com.y2gcoder.app.global.util;

import com.y2gcoder.app.global.config.security.OAuth2Config;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

@RequiredArgsConstructor
@Component
public class RefreshTokenCookieUtils {
	private final OAuth2Config oAuth2Config;

	public ResponseCookie generateRefreshTokenCookie(String refreshToken) {
		return CookieUtils
				.generateResponseCookie(
						oAuth2Config.getAuth().getRefreshCookieKey(),
						refreshToken,
						oAuth2Config.getAuth().getRefreshTokenValidityInMs() / 1000
				);
	}

	public ResponseCookie generateSignOutCookie() {
		return CookieUtils
				.generateResponseCookie(
						oAuth2Config.getAuth().getRefreshCookieKey(),
						"",
						1
				);
	}
}
