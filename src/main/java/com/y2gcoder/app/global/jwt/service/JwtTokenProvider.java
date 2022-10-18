package com.y2gcoder.app.global.jwt.service;

import com.y2gcoder.app.domain.member.constant.MemberRole;
import com.y2gcoder.app.global.jwt.constant.ClaimKeyType;
import com.y2gcoder.app.global.jwt.constant.GrantType;
import com.y2gcoder.app.global.jwt.constant.TokenType;
import com.y2gcoder.app.global.jwt.dto.JwtTokenDto;
import com.y2gcoder.app.global.config.security.OAuth2Config;
import com.y2gcoder.app.global.config.security.dto.CustomUserDetails;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SecurityException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

@RequiredArgsConstructor
@Slf4j
@Service
public class JwtTokenProvider {
	private final OAuth2Config oAuth2Config;


	public JwtTokenDto createJwtToken(String memberId, MemberRole memberRole) {
		Date accessTokenExpireTime = createAccessTokenExpireTime();
		Date refreshTokenExpireTime = createRefreshTokenExpireTime();

		String accessToken = createAccessToken(memberId, memberRole, accessTokenExpireTime);
		String refreshToken = createRefreshToken(memberId, refreshTokenExpireTime);

		return JwtTokenDto.builder()
				.grantType(GrantType.BEARER.getType())
				.accessToken(accessToken)
				.accessTokenExpireTime(accessTokenExpireTime)
				.refreshToken(refreshToken)
				.refreshTokenExpireTime(refreshTokenExpireTime)
				.build();
	}

	public Date createAccessTokenExpireTime() {
		return new Date(new Date().getTime() + oAuth2Config.getAuth().getAccessTokenValidityInMs());
	}
	private Date createRefreshTokenExpireTime() {
		return new Date(new Date().getTime() + oAuth2Config.getAuth().getRefreshTokenValidityInMs());
	}

	public String createAccessToken(String memberId, MemberRole memberRole, Date accessTokenExpireTime) {
		SecretKey secretKey = createSecretKey();

		return Jwts.builder()
				.setSubject(TokenType.access.name())
				.setIssuedAt(new Date())
				.setExpiration(accessTokenExpireTime)
				.claim(ClaimKeyType.MEMBER_ID.getType(), memberId)
				.claim(ClaimKeyType.ROLE.getType(), memberRole.getRole())
				.signWith(secretKey, SignatureAlgorithm.HS512)
				.setHeaderParam("typ", "JWT")
				.compact();
	}

	private String createRefreshToken(String memberId, Date refreshTokenExpireTime) {
		SecretKey secretKey = createSecretKey();
		return Jwts.builder()
				.setSubject(TokenType.refresh.name())
				.setIssuedAt(new Date())
				.setExpiration(refreshTokenExpireTime)
				.claim(ClaimKeyType.MEMBER_ID.getType(), memberId)
				.signWith(secretKey, SignatureAlgorithm.HS512)
				.setHeaderParam("typ", "JWT")
				.compact();
	}

	public boolean validateToken(String token) {
		try {
			Jwts.parserBuilder().setSigningKey(createSecretKey()).build().parseClaimsJws(token)
					.getBody().getExpiration();
			return true;
		} catch (SecurityException | MalformedJwtException e) {
			log.error("잘못된 JWT 서명입니다.");
		} catch (ExpiredJwtException e) {
			log.error("만료된 JWT 토큰입니다.");
		} catch (UnsupportedJwtException e) {
			log.error("지원하지 않는 JWT 토큰입니다.");
		} catch (IllegalArgumentException e) {
			log.error("JWT 토큰이 잘못되었습니다.");
		}
		return false;
	}

	public UsernamePasswordAuthenticationToken getAuthentication(String accessToken) {
		Claims claims = parseClaims(accessToken);
		String stringMemberId = claims.get(ClaimKeyType.MEMBER_ID.getType(), String.class);
		Long memberId = Long.parseLong(stringMemberId);
		List<SimpleGrantedAuthority> authorities = Arrays
				.stream(claims.get(ClaimKeyType.ROLE.getType(), String.class).split(","))
				.map(SimpleGrantedAuthority::new).collect(Collectors.toList());

		CustomUserDetails customUserDetails = new CustomUserDetails(memberId, "", "", authorities);

		return new UsernamePasswordAuthenticationToken(customUserDetails, "", authorities);
	}

	public Claims parseClaims(String token) {
		return Jwts.parserBuilder()
				.setSigningKey(createSecretKey()).build().parseClaimsJws(token).getBody();
	}

	private SecretKey createSecretKey() {
		return Keys.hmacShaKeyFor(Decoders.BASE64.decode(oAuth2Config.getAuth().getTokenSecret()));
	}
}
