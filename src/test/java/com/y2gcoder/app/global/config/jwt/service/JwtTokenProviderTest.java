package com.y2gcoder.app.global.config.jwt.service;

import com.y2gcoder.app.domain.member.constant.MemberRole;
import com.y2gcoder.app.global.config.PropertiesConfiguration;
import com.y2gcoder.app.global.config.security.OAuth2Config;
import com.y2gcoder.app.global.config.security.dto.CustomUserDetails;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.ConfigDataApplicationContextInitializer;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(SpringExtension.class)
@EnableConfigurationProperties(value = OAuth2Config.class)
@ContextConfiguration(initializers = ConfigDataApplicationContextInitializer.class, classes = PropertiesConfiguration.class)
class JwtTokenProviderTest {

	@Autowired
	OAuth2Config oAuth2Config;
	JwtTokenProvider jwtTokenProvider;

	@BeforeEach
	void beforeEach() {
		jwtTokenProvider = new JwtTokenProvider(oAuth2Config);
	}

	@Test
	@DisplayName("JwtTokenProvider: createAccessTokenExpireTime, 성공")
	void whenCreateAccessTokenExpireTime_thenReturnDate() {
		//given
		//when
		Date result = jwtTokenProvider.createAccessTokenExpireTime();
		//then
		assertThat(result).isInstanceOf(Date.class);
		assertThat(result)
				.isEqualToIgnoringMillis(new Date(new Date().getTime() + oAuth2Config.getAuth().getAccessTokenValidityInMs()));
	}

	@Test
	@DisplayName("JwtTokenProvider: createAccessToken, 유효한 토큰")
	void whenCreateAccessToken_thenValidToken() {
		//given
		String memberId = String.valueOf(1L);
		MemberRole memberRole = MemberRole.USER;
		Date accessTokenExpireTime = jwtTokenProvider.createAccessTokenExpireTime();

		//when
		String accessToken = jwtTokenProvider.createAccessToken(memberId, memberRole, accessTokenExpireTime);

		//then
		assertThat(jwtTokenProvider.validateToken(accessToken)).isTrue();
	}

	@Test
	@DisplayName("JwtTokenProvider: getAuthentication, 성공")
	void whenGetAuthentication_thenReturnValidAuthentication() {
		//given
		String memberId = String.valueOf(1L);
		MemberRole memberRole = MemberRole.USER;
		Date accessTokenExpireTime = jwtTokenProvider.createAccessTokenExpireTime();
		String accessToken = jwtTokenProvider.createAccessToken(memberId, memberRole, accessTokenExpireTime);

		//when
		UsernamePasswordAuthenticationToken authentication = jwtTokenProvider.getAuthentication(accessToken);

		//then
		String name = authentication.getName();
		CustomUserDetails principal = (CustomUserDetails) authentication.getPrincipal();
		List<String> result = principal.getAuthorities().stream()
				.map(GrantedAuthority::getAuthority).collect(Collectors.toList());

		assertThat(name).isEqualTo(memberId);
		assertThat(result).contains(memberRole.getRole());

	}
}