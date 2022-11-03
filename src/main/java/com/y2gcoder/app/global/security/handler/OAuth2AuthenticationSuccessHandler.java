package com.y2gcoder.app.global.security.handler;

import com.y2gcoder.app.domain.member.constant.MemberRole;
import com.y2gcoder.app.domain.token.service.TokenService;
import com.y2gcoder.app.global.config.security.OAuth2Config;
import com.y2gcoder.app.global.error.ErrorCode;
import com.y2gcoder.app.global.error.exception.AuthenticationException;
import com.y2gcoder.app.global.jwt.dto.JwtTokenDto;
import com.y2gcoder.app.global.jwt.service.JwtTokenProvider;
import com.y2gcoder.app.global.security.dto.CustomUserDetails;
import com.y2gcoder.app.global.security.repository.CustomAuthorizationRequestRepository;
import com.y2gcoder.app.global.util.CookieUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.Optional;

@Slf4j
@RequiredArgsConstructor
@Component
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
	private final OAuth2Config oAuth2Config;
	private final TokenService tokenService;
	private final CustomAuthorizationRequestRepository authorizationRequestRepository;
	private final JwtTokenProvider jwtTokenProvider;

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException, ServletException {
		if (response.isCommitted()) {
			log.debug("Response has already been committed!!!!");
			return;
		}

		String targetUrl = determineTargetUrl(request, response, authentication);
		clearAuthenticationAttributes(request, response);
		getRedirectStrategy().sendRedirect(request, response, targetUrl);
	}

	protected String determineTargetUrl(
			HttpServletRequest request, HttpServletResponse response, Authentication authentication
	) {
		Optional<String> redirectUri = CookieUtils
				.getCookie(request, CustomAuthorizationRequestRepository.REDIRECT_URI_PARAM_COOKIE_NAME).map(Cookie::getValue);

		if (redirectUri.isPresent() && !isAuthorizedRedirectUri(redirectUri.get())) {
			throw new AuthenticationException(ErrorCode.IS_NOT_REDIRECT_URI);
		}

		String targetUrl = redirectUri.orElse(getDefaultTargetUrl());

		// 토큰 생성
		CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
		String memberId = userDetails.getName();
		MemberRole memberRole = userDetails.getAuthorities()
				.stream().map(GrantedAuthority::getAuthority).map(MemberRole::from).findFirst().orElse(null);

		JwtTokenDto jwtTokenDto = jwtTokenProvider.createJwtToken(memberId, memberRole);
		tokenService.updateRefreshToken(
				Long.parseLong(memberId),
				jwtTokenDto.getRefreshToken(),
				jwtTokenDto.getRefreshTokenExpireTime()
		);

		return UriComponentsBuilder.fromUriString(targetUrl)
				.queryParam("grant", jwtTokenDto.getGrantType())
				.queryParam("access", jwtTokenDto.getAccessToken())
				.queryParam("refresh", jwtTokenDto.getRefreshToken())
				.build().toUriString();
	}

	private boolean isAuthorizedRedirectUri(String uri) {
		URI clientRedirectUri = URI.create(uri);

		return oAuth2Config.getOAuth2().getAuthorizedRedirectUris()
				.stream()
				.anyMatch(authorizedRedirectUri -> {
					URI authorizedURI = URI.create(authorizedRedirectUri);
					return authorizedURI.getHost().equalsIgnoreCase(clientRedirectUri.getHost())
							&& authorizedURI.getPort() == clientRedirectUri.getPort();
				});
	}

	protected void clearAuthenticationAttributes(HttpServletRequest request, HttpServletResponse response) {
		super.clearAuthenticationAttributes(request);
		authorizationRequestRepository.removeAuthorizationRequestCookies(request, response);
	}
}
