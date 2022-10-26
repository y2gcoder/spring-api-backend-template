package com.y2gcoder.app.global.jwt.service;

import com.y2gcoder.app.domain.member.constant.MemberRole;
import com.y2gcoder.app.global.config.PropertiesConfiguration;
import com.y2gcoder.app.global.config.security.OAuth2Config;
import com.y2gcoder.app.global.jwt.dto.JwtTokenDto;
import com.y2gcoder.app.global.security.dto.CustomUserDetails;
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

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Set;
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
	@DisplayName("JwtTokenProvider: createAccessToken, 유효한 토큰")
	void whenCreateAccessToken_thenValidToken() {
		//given
		String memberId = String.valueOf(1L);
		MemberRole memberRole = MemberRole.USER;
		Date accessTokenExpireTime = jwtTokenProvider.createAccessTokenExpireTime();

		//when
		String accessToken = jwtTokenProvider.createAccessToken(memberId, memberRole, accessTokenExpireTime);

		//then
		assertThat(jwtTokenProvider.validateAccessToken(accessToken)).isTrue();
	}

	@Test
	@DisplayName("JwtTokenProvider: createJwtToken, 짧은 시간에 10회 반복시 똑같은 토큰 반환됨.")
	void whenCreateJwtTokenFor10times_thenDuplicateToken() {
		//given
		String memberId = String.valueOf(1L);
		MemberRole memberRole = MemberRole.USER;
		//when
		List<JwtTokenDto> list = new ArrayList<>();
		for (int i = 0; i < 20; i++) {
			JwtTokenDto jwtTokenDto = jwtTokenProvider.createJwtToken(memberId, memberRole);
			list.add(jwtTokenDto);
		}
		//then
		Set<String> resultSet = list.stream().map(JwtTokenDto::getAccessToken).collect(Collectors.toSet());
		assertThat(list.size()).isGreaterThan(resultSet.size());

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

	@Test
	@DisplayName("JwtTokenProvider: validateAccessToken, 성공")
	void whenValidateAccessToken_thenSuccsss() {
		//given
		String memberId = String.valueOf(1L);
		MemberRole memberRole = MemberRole.USER;
		JwtTokenDto jwtTokenDto = jwtTokenProvider.createJwtToken(memberId, memberRole);

		//when
		boolean result = jwtTokenProvider.validateAccessToken(jwtTokenDto.getAccessToken());

		//then
		assertThat(result).isTrue();
	}

	@Test
	@DisplayName("JwtTokenProvider: validateAccessToken, 실패, 리프레시 토큰일 때")
	void givenRefreshToken_whenValidateAccessToken_thenFalse() {
		//given
		String memberId = String.valueOf(1L);
		MemberRole memberRole = MemberRole.USER;
		JwtTokenDto jwtTokenDto = jwtTokenProvider.createJwtToken(memberId, memberRole);

		//when
		boolean result = jwtTokenProvider.validateAccessToken(jwtTokenDto.getRefreshToken());

		//then
		assertThat(result).isFalse();
	}

	@Test
	@DisplayName("JwtTokenProvider: validateRefreshToken, 성공")
	void whenValidateRefreshToken_thenSuccsss() {
		//given
		String memberId = String.valueOf(1L);
		MemberRole memberRole = MemberRole.USER;
		JwtTokenDto jwtTokenDto = jwtTokenProvider.createJwtToken(memberId, memberRole);

		//when
		boolean result = jwtTokenProvider.validateRefreshToken(jwtTokenDto.getRefreshToken());

		//then
		assertThat(result).isTrue();
	}



	@Test
	@DisplayName("JwtTokenProvider: validateRefreshToken, 실패, 액세스 토큰일 때")
	void givenAccessToken_whenValidateRefreshToken_thenFalse() {
		//given
		String memberId = String.valueOf(1L);
		MemberRole memberRole = MemberRole.USER;
		JwtTokenDto jwtTokenDto = jwtTokenProvider.createJwtToken(memberId, memberRole);

		//when
		boolean result = jwtTokenProvider.validateRefreshToken(jwtTokenDto.getAccessToken());

		//then
		assertThat(result).isFalse();
	}
}
