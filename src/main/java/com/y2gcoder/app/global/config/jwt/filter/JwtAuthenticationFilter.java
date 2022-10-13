package com.y2gcoder.app.global.config.jwt.filter;

import com.y2gcoder.app.global.config.jwt.service.JwtTokenProvider;
import com.y2gcoder.app.global.util.JwtUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
	private final JwtTokenProvider jwtTokenProvider;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
		String authorizationHeader = request.getHeader("Authorization");
		String jwt = JwtUtils.getTokenFromRequest(authorizationHeader);

		if (StringUtils.hasText(jwt) && jwtTokenProvider.validateToken(jwt)) {
			UsernamePasswordAuthenticationToken authentication = jwtTokenProvider.getAuthentication(jwt);
			SecurityContextHolder.getContext().setAuthentication(authentication);
			log.debug("JWT로 {}의 인증정보 저장", authentication.getName());
		} else {
			log.debug("유효한 JWT 토큰이 없습니다.");
		}

		filterChain.doFilter(request, response);
	}

}
