package com.y2gcoder.app.global.util;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.util.SerializationUtils;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Base64;
import java.util.Optional;

public class CookieUtils {

	public static Optional<Cookie> getCookie(HttpServletRequest request, String name) {
		Cookie[] cookies = request.getCookies();
		if (cookies != null && cookies.length > 0) {
			for (Cookie cookie : cookies) {
				if (cookie.getName().equals(name)) {
					return Optional.of(cookie);
				}
			}
		}
		return Optional.empty();
	}

	public static void addCookie(HttpServletResponse response, String name, String value, int maxAge) {
		Cookie cookie = new Cookie(name, value);
		cookie.setPath("/");
		cookie.setHttpOnly(true);
		cookie.setMaxAge(maxAge);
		response.addCookie(cookie);
	}

	public static void deleteCookie(HttpServletRequest request, HttpServletResponse response, String name) {
		Cookie[] cookies = request.getCookies();
		if (cookies != null && cookies.length > 0) {
			for (Cookie cookie : cookies) {
				if (cookie.getName().equals(name)) {
					cookie.setValue("");
					cookie.setPath("/");
					cookie.setMaxAge(0);
					response.addCookie(cookie);
				}
			}
		}
	}

	public static String serialize(Object object) {
		return Base64.getUrlEncoder()
				.encodeToString(SerializationUtils.serialize(object));
	}

	public static <T> T deserialize(Cookie cookie, Class<T> clazz) {
		return clazz.cast(SerializationUtils.deserialize(
				Base64.getUrlDecoder().decode(cookie.getValue())
		));
	}

	public static void addRefreshTokenCookie(
			HttpServletResponse response,
			String refreshCookieKey,
			String refreshToken,
			long refreshTokenValidityInMs
	) {
		ResponseCookie cookie = ResponseCookie.from(refreshCookieKey, refreshToken)
				.httpOnly(true)
				.secure(true)
				.sameSite("Lax")
				.maxAge(refreshTokenValidityInMs / 1000)
				.path("/")
				.build();

		response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
	}

}
