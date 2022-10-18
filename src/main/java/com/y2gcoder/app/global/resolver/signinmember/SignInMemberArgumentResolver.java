package com.y2gcoder.app.global.resolver.signinmember;

import com.y2gcoder.app.domain.member.constant.MemberRole;
import com.y2gcoder.app.global.config.jwt.constant.ClaimKeyType;
import com.y2gcoder.app.global.config.jwt.service.JwtTokenProvider;
import com.y2gcoder.app.global.util.JwtUtils;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.core.MethodParameter;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

import javax.servlet.http.HttpServletRequest;

@RequiredArgsConstructor
@Component
public class SignInMemberArgumentResolver implements HandlerMethodArgumentResolver {
	private final JwtTokenProvider jwtTokenProvider;


	@Override
	public boolean supportsParameter(MethodParameter parameter) {
		boolean hasSignInMemberAnnotation = parameter.hasParameterAnnotation(SignInMember.class);
		boolean hasSignInMemberDto = SignInMemberDto.class.isAssignableFrom(parameter.getParameterType());
		return hasSignInMemberAnnotation && hasSignInMemberDto;
	}

	@Override
	public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer mavContainer, NativeWebRequest webRequest, WebDataBinderFactory binderFactory) throws Exception {
		HttpServletRequest request = (HttpServletRequest) webRequest.getNativeRequest();
		String authorizationHeader = request.getHeader("Authorization");
		String jwt = JwtUtils.getTokenFromRequest(authorizationHeader);

		Claims claims = jwtTokenProvider.parseClaims(jwt);
		Long memberId = Long.parseLong(claims.get(ClaimKeyType.MEMBER_ID.getType(), String.class));
		String role = claims.get(ClaimKeyType.ROLE.getType(), String.class);
		return SignInMemberDto.builder()
				.memberId(memberId)
				.role(MemberRole.from(role))
				.build();
	}
}
