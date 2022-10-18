package com.y2gcoder.app.global.security.handler;

import com.y2gcoder.app.global.security.repository.CustomAuthorizationRequestRepository;
import com.y2gcoder.app.global.util.CookieUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RequiredArgsConstructor
@Component
public class OAuth2AuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {
	private final CustomAuthorizationRequestRepository authorizationRequestRepository;

	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
		String targetUrl = CookieUtils.getCookie(request, CustomAuthorizationRequestRepository.REDIRECT_URI_PARAM_COOKIE_NAME)
				.map(Cookie::getValue)
				.orElse("/");

		targetUrl = UriComponentsBuilder.fromUriString(targetUrl)
				.queryParam("error", exception.getLocalizedMessage())
				.build().toUriString();

		authorizationRequestRepository.removeAuthorizationRequestCookies(request, response);
		getRedirectStrategy().sendRedirect(request, response, targetUrl);
	}
}
