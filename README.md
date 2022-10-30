# Spring Boot로 만드는 API 서버 템플릿 (1) - 시작

# 제작 배경

개발자로 일하면서 봤던 수많은 소프트웨어 개발 관련 용어들 중 개인적으로 제일 마음에 들었던 용어 **DRY**(Don't repeat yourself)였다. 언젠가부터 프로젝트를 시작할 때마다 환경 설정하는 과정이 너무 지루하게 느껴졌다. 똑같은 라이브러리를 추가하고, 해당 라이브러리에서 자주 사용하는 설정을 추가해주는 과정을 반복하는 것은 내가 좋아하는 DRY한 과정이 아니었다. 

그래서 이번 기회에 개인적으로 스프링 부트를 이용해 프로젝트를 진행할 때마다 반복적으로 했던 기본 설정들을 Github 템플릿으로 만들어보기로 했다. 템플릿으로 만들어두면 나중에 개인 프로젝트를 진행할 때 초반 설정에 드는 시간을 절약할 수 있을 것이란 생각이 들었다. [인프런 강의](https://www.inflearn.com/course/%EC%8A%A4%ED%94%84%EB%A7%81%EB%B6%80%ED%8A%B8-api-%ED%85%9C%ED%94%8C%EB%A6%BF)을 참고해서 내 개인 설정과, 평소 적용하고 싶었던 라이브러리와 설정을 추가해서 내 개인 템플릿을 만들기로 했다. 


---


# 제품 소개

github repo: https://github.com/y2gcoder/spring-api-backend-template

## 패키지 구조

![구조](https://velog.velcdn.com/images/y2gcoder/post/852dc9ad-f87b-4691-b06a-8dea69626d55/image.png)


### java

해당 템플릿에서 사용한 패키지 구조는 역할에 따라 패키지를 나누고, 그 안에 도메인 별로 패키지를 나눈 패키지 구조다. 도메인 별로 나눈 패키지 안에서는 계층형 아키텍처를 적용해 위치에 따라 controller, service, repository 패키지로 나눴다. dto 패키지들은 순환참조를 피하기 위해 의존관계에 따라 위치했다. 

- api: 클라이언트에게 제공할 API 엔드포인트들이 존재하는 패키지 
- domain: 도메인에 따라 핵심 비즈니스 로직을 구현한 클래스들이 존재하는 패키지
- global: 애플리케이션 내에서 전체적으로 사용하는 클래스들이 존재하는 패키지
  - config: 애플리케이션의 설정과 관련한 클래스들이 존재하는 패키지
  - error: 예외 처리와 관련한 클래스들이 존재하는 패키지
  - jwt: JWT 기반의 인증 처리를 담당하는 클래스들이 존재하는 패키지
  - resolver: argument resolver 와 관련한 클래스들이 존재하는 패키지
  - security: Spring Security, OAuth2 처리와 관련한 클래스들이 존재하는 패키지
  - util: 유틸리티성 클래스들이 존재하는 패키지
- infra: SMS, 이메일 등의 외부 서비스와 관련한 클래스들이 존재하는 패키지

### resources

- application-*.yml: 애플리케이션 설정 파일
- lucy-xss-**.yml: naver에서 만든 xss 공격에 대응하는 라이브러리 [lucy-xss-servlet](https://github.com/naver/lucy-xss-servlet-filter) 의 설정파일


---

## 핵심 기능

### 도메인

#### Member

```java
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
public class Member extends BaseTimeEntity {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@Column(unique = true, length = 50, nullable = false)
	private String email;

	@Column(length = 200)
	private String password;

	private String nickname;

	private String profile;

	@Enumerated(EnumType.STRING)
	@Column(nullable = false, length = 10)
	private MemberRole role;

	@Enumerated(EnumType.STRING)
	@Column(nullable = false, length = 10)
	private AuthProvider provider;

	private String refreshToken;

	private LocalDateTime tokenExpirationTime;

	@Builder
	public Member(
			String email, String password, String nickname, String profile, MemberRole role, AuthProvider provider
	) {
		this.email = email;
		this.password = password;
		this.nickname = nickname;
		this.profile = profile;
		this.role = role;
		this.provider = provider;
	}

	public void updateRefreshToken(String refreshToken, LocalDateTime tokenExpirationTime) {
		this.refreshToken = refreshToken;
		this.tokenExpirationTime = tokenExpirationTime;
	}
}
```

간단하게 Member 엔티티에 모든 정보를 포함하는 방식으로 설계했다. 

> Q. Member 엔티티에 소셜 로그인 정보, Refresh Token에 대한 정보를 같이 담은 이유?
A. 현재의 간단한 설계에서는 굳이 소셜 로그인 정보 테이블, Refresh Token 정보 테이블을 나눌 필요가 없다고 생각해 같이 합쳤다. 추후 업데이트하면서 필요하다면 따로 나누고 관계 설정을 하는 방향으로 진행하려 한다.



### 회원가입(로컬)

#### AuthService

```java

	@Transactional
	public void signUp(SignUpRequest request) {
		validateSignUpInfo(request);
		Member member = Member.builder()
				.email(request.getEmail())
				.password(passwordEncoder.encode(request.getPassword()))
				.role(MemberRole.USER)
				.provider(AuthProvider.local)
				.build();
		memberService.registerMember(member);
	}

	private void validateSignUpInfo(SignUpRequest request) {
		if (memberService.existsMemberByEmail(request.getEmail())) {
			throw new BusinessException(ErrorCode.ALREADY_REGISTERED_MEMBER);
		}
	}
```

이메일과 비밀번호만 사용해서 회원가입하는 간단한 기능이다. 기존 회원과의 이메일 중복 여부만 체크하고 바로 저장한다. 

### 로그인(로컬)

#### AuthServie

```java

	@Transactional
	public JwtTokenDto signIn(SignInDto.Request request) {
		Member member = memberService.findMemberByEmail(request.getEmail());
		validateMemberAuthProvider(member.getProvider());
		validatePassword(request.getPassword(), member.getPassword());
		// 토큰 만들기(access, refresh)
		JwtTokenDto jwtTokenDto = jwtTokenProvider.createJwtToken(String.valueOf(member.getId()), member.getRole());
		// refresh token 저장 (DB)
		memberService.updateRefreshToken(
				member.getId(),
				jwtTokenDto.getRefreshToken(),
				jwtTokenDto.getRefreshTokenExpireTime()
		);

		return jwtTokenDto;
	}

	private void validateMemberAuthProvider(AuthProvider provider) {
		if (!provider.equals(AuthProvider.local)) {
			throw new AuthenticationException(ErrorCode.SOCIAL_SIGN_IN_MEMBER);
		}
	}

	private void validatePassword(String requestPassword, String memberPassword) {
		if (!passwordEncoder.matches(requestPassword, memberPassword)) {
			throw new AuthenticationException(ErrorCode.MISMATCH_PASSWORD);
		}
	}

```

이메일과 비밀번호를 사용해서 로그인한다. 입력값의 유효성 검사를 제외하고 유효성 검사를 총 세 번 진행한다.

1. email로 가입한 회원이 있는지
2. 해당 회원이 아이디/비밀번호(로컬) 회원인지
3. 입력한 비밀번호와 DB에 저장한 비밀번호가 일치하는지

유효성 검사를 모두 통과하면 JWT를 이용해 Access Token과 Refresh Token을 생성한다. Access Token은 응답 DTO에 담아 response body로 클라이언트에 내보내고, Refresh Token은 해당 Member 테이블에 저장하고, 

#### AuthController
```java

	@PostMapping("/sign-in")
	public ResponseEntity<SignInDto.Response> signIn(@Valid @RequestBody SignInDto.Request req) {
		JwtTokenDto jwtTokenDto = authService.signIn(req);
		SignInDto.Response result = SignInDto.Response.builder()
				.grantType(jwtTokenDto.getGrantType())
				.accessToken(jwtTokenDto.getAccessToken())
				.accessTokenExpireTime(jwtTokenDto.getAccessTokenExpireTime())
				.build();

		//Cookie에 refresh token 저장!!
		ResponseCookie refreshTokenCookie = refreshTokenCookieUtils
				.generateRefreshTokenCookie(jwtTokenDto.getRefreshToken());

		return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString()).body(result);
	}

```

Cookie에도 저장하여 클라이언트에 내보낸다.

> Q. Refresh Token를 Cookie에 담아 클라이언트에 제공하는 이유?
A. 해당 템플릿은 웹 애플리케이션에 대한 API 서버 환경을 구성해주는 템플릿이다. 그래서 Refresh Token의 저장위치로 local storage, cookie 2곳을 고민했다. 각각 장단점이 있었고, Cookie에 저장하기로 했다.

> Q. Refresh Token을 DB에도 저장한 이유?
A. JWT를 사용하는데 DB에도 저장하는 것은 사실 token을 사용하는 의미가 살짝 퇴색한다고 생각했다. 그럼에도 불구하고 DB에 Refresh Token을 저장하는 이유는 결국 보안적인 측면을 의식했기 때문이다. 악의를 가진 누군가가 Cookie에 있는 Refresh Token을 탈취했을 상황을 생각했다. 그 때는 수동으로라도 Refresh Token을 무력화해줄 필요가 있었기 때문에, DB에도 Refresh Token을 저장해 대조하는 방식으로 개발했다.

### 소셜 로그인

소셜 로그인 부분을 직접 구현할 지, Spring Security + OAuth2 Client를 사용할 지 많이 고민했다. Spring Security + OAuth2로 구현한 이유는 2가지가 있었다.

1. Spring Security + JWT 조합을 사용해본 경험을 활용해보고 싶었다. 이전 회사에서 사내 커뮤니티 앱 프로젝트를 진행했던 적이 있었다. 그 때는 사원번호와 비밀번호를 기반으로 한 로그인만 가능했기 때문에, OAuth2 인증이 불필요했다. 그래서 Spring Security + JWT 조합을 사용해서 서버의 인증부를 구현했다. 이전 경험에 더해서 OAuth2 인증만 추가하면 되기에 해보고 싶었다.
2. 잘 만들어져 있는 라이브러리들을 이용해 만들어보고 싶었다. 직접 구현하는 것이 좋을 수는 있겠으나, 일단 잘 만들어놓은 라이브러리를 사용하면서 해당 라이브러리에서 전체적인 인증 과정을 어떻게 구현했는지 분석해보고 싶었다. 해당 라이브러리의 인증 과정을 참고하고 정리하면 추후에 직접 내가 인증부를 구현해야 할 때 더 좋은 설계를 할 수 있을 것 같았다.

#### SecurityConfig

```java

@Slf4j
@RequiredArgsConstructor
@EnableGlobalMethodSecurity(
		securedEnabled = true
		, prePostEnabled = true
		, jsr250Enabled = true
)
@EnableWebSecurity
@Configuration
public class SecurityConfig {
	private final CustomAuthorizationRequestRepository customAuthorizationRequestRepository;
	private final CustomOAuth2UserService customOAuth2UserService;
	private final OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler;
	private final OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;
	private final JwtAuthenticationFilter jwtAuthenticationFilter;
	private final CustomAuthenticationEntrypoint customAuthenticationEntrypoint;
	private final CustomAccessDeniedHandler customAccessDeniedHandler;

	@Bean
	public PasswordEncoder passwordEncoder() {
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http.authorizeRequests()
				...
				.anyRequest().authenticated();

		http.cors()
				.and()
				.csrf().disable()
				.httpBasic().disable()
				.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

		http.formLogin().disable()
				.oauth2Login()
				.authorizationEndpoint()
				.authorizationRequestRepository(customAuthorizationRequestRepository)
				.and()
				.userInfoEndpoint()
				.userService(customOAuth2UserService)
				.and()
				.successHandler(oAuth2AuthenticationSuccessHandler)
				.failureHandler(oAuth2AuthenticationFailureHandler);

		http.exceptionHandling()
				.authenticationEntryPoint(customAuthenticationEntrypoint)
				.accessDeniedHandler(customAccessDeniedHandler);

		http.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

		return http.build();
	}
}

```

Spring Security + OAuth2에 대한 전반적인 설정이다. 

#### CustomAuthorizationRequestRepository

```java

@Component
public class CustomAuthorizationRequestRepository implements AuthorizationRequestRepository<OAuth2AuthorizationRequest> {
	public static final String OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME = "oauth2_auth_request";
	public static final String REDIRECT_URI_PARAM_COOKIE_NAME = "redirect_uri";

	private static final int COOKIE_EXPIRE_SECONDS = 3600;
	@Override
	public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
		return CookieUtils.getCookie(request, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME)
				.map(cookie -> CookieUtils.deserialize(cookie, OAuth2AuthorizationRequest.class))
				.orElse(null);
	}

	@Override
	public void saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest, HttpServletRequest request, HttpServletResponse response) {
		if (authorizationRequest == null) {
			CookieUtils.deleteCookie(request, response, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME);
			CookieUtils.deleteCookie(request, response, REDIRECT_URI_PARAM_COOKIE_NAME);
			return;
		}

		CookieUtils.addCookie(response, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME, CookieUtils.serialize(authorizationRequest), COOKIE_EXPIRE_SECONDS);
		String redirectUriAfterLogin = request.getParameter(REDIRECT_URI_PARAM_COOKIE_NAME);
		if (StringUtils.isNotBlank(redirectUriAfterLogin)) {
			CookieUtils.addCookie(response, REDIRECT_URI_PARAM_COOKIE_NAME, redirectUriAfterLogin, COOKIE_EXPIRE_SECONDS);
		}
	}

	@Override
	public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request) {
		return this.loadAuthorizationRequest(request);
	}

	public void removeAuthorizationRequestCookies(HttpServletRequest request, HttpServletResponse response) {
		CookieUtils.deleteCookie(request, response, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME);
		CookieUtils.deleteCookie(request, response, REDIRECT_URI_PARAM_COOKIE_NAME);
	}
}

```

인가 응답을 연계 하고 검증할 때는 기본적으로 세션을 사용한다. 그것을 Cookie로 바꾸어주는 역할을 한다.  
>Q. 그냥 세션을 사용하면 되는데 왜 쿠키 기반으로 바꾸었나?
A. 해당 프로젝트에서는 JWT를 사용한 토큰 방식 인증을 사용하기 때문에 세션이 불필요하다. 그래서 SessionCreatePolicy.STATELESS 를 사용해서 세션을 아예 사용하지 않도록 설정했다. 세션을 사용하지 않도록 설정했기 때문에 대안으로 쿠키를 사용하고자 했다. 

#### CustomOAuth2UserService

```java

@Slf4j
@RequiredArgsConstructor
@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {
	private final MemberRepository memberRepository;

	@Override
	public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
		OAuth2User oAuth2User = super.loadUser(userRequest);
		return processOAuth2User(userRequest, oAuth2User);
	}

	private OAuth2User processOAuth2User(OAuth2UserRequest userRequest, OAuth2User oAuth2User) {
		String registrationId = userRequest.getClientRegistration().getRegistrationId();
		OAuth2Attributes oAuth2Attributes = OAuth2AttributeFactory.getOAuth2Attributes(
				registrationId,
				oAuth2User.getAttributes()
		);
		AuthProvider authProvider = AuthProvider.valueOf(registrationId);
		Optional<Member> optionalMember = memberRepository.findByEmail(oAuth2Attributes.getEmail());
		Member member;
		if (optionalMember.isPresent()) {
			member = optionalMember.get();
			if (!member.getProvider().equals(authProvider)) {
				throw new AuthenticationException(ErrorCode.INVALID_AUTH_PROVIDER);
			}
		} else {
			member = registerMember(authProvider, oAuth2Attributes);
		}

		return CustomUserDetails.create(member);
	}

	private Member registerMember(AuthProvider authProvider, OAuth2Attributes oAuth2Attributes) {
		Member member = Member.builder()
				.email(oAuth2Attributes.getEmail())
				.role(MemberRole.USER)
				.nickname(oAuth2Attributes.getName())
				.profile(oAuth2Attributes.getImageUrl())
				.provider(authProvider)
				.build();
		return memberRepository.save(member);
	}

}

```

소셜 로그인 시 OAuth2UserRequest를 이용해서 회원 정보를 저장하고, 유저 정보를 반환해주거나, 이미 해당 회원 정보가 이미 존재할 때는 유저 정보만 반환해준다. 

#### OAuth2AuthenticationSuccessHandler

```java

@Slf4j
@RequiredArgsConstructor
@Component
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
	private final OAuth2Config oAuth2Config;
	private final MemberService memberService;
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
		memberService.updateRefreshToken(
				Long.parseLong(memberId),
				jwtTokenDto.getRefreshToken(),
				jwtTokenDto.getRefreshTokenExpireTime()
		);

		ResponseCookie refreshTokenCookie = CookieUtils.generateResponseCookie(
				oAuth2Config.getAuth().getRefreshCookieKey(),
				jwtTokenDto.getRefreshToken(),
				oAuth2Config.getAuth().getRefreshTokenValidityInMs() / 1000
		);

		response.addHeader(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString());

		return UriComponentsBuilder.fromUriString(targetUrl)
				.queryParam("token", jwtTokenDto.getAccessToken())
				.queryParam("grant", jwtTokenDto.getGrantType())
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

```

OAuth2 로그인에 성공했을 때 호출하는 Handler로, JWT를 생성해서 Refresh Token 정보를 해당 유저 테이블에 저장하고 Access Token과 Grant Type을 Redirect URI에 넣어 클라이언트에 보내준다.


#### JwtAuthenticationFilter

```java

@Slf4j
@RequiredArgsConstructor
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
	private final JwtTokenProvider jwtTokenProvider;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
		String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
		String jwt = JwtUtils.getTokenFromRequest(authorizationHeader);

		if (StringUtils.hasText(jwt) && jwtTokenProvider.validateAccessToken(jwt)) {
			UsernamePasswordAuthenticationToken authentication = jwtTokenProvider.getAuthentication(jwt);
			SecurityContextHolder.getContext().setAuthentication(authentication);
			log.debug("JWT로 {}의 인증정보 저장", authentication.getName());
		}

		filterChain.doFilter(request, response);
	}

}

```

인증 헤더에 담긴 JWT 토큰을 검증하고 통과했을 때 인증정보를 생성해 저장해주는 필터입니다. 

### 토큰 재발급

쿠키로 받은 Refresh Token을 검증해서 통과한다면, Access Token을 갱신해서 발급해준다. 

#### AuthController

```java

@PostMapping("/refresh")
public ResponseEntity<TokenRefreshResponse> refreshToken(@CookieValue("refreshtoken") String refreshToken) {

	TokenRefreshResponse response = authService.refreshToken(refreshToken);
    return ResponseEntity.ok(response);
}

```

service에서 토큰 갱신 결과를 생성해서 리턴해준다.

#### AuthService

```java

	public TokenRefreshResponse refreshToken(String refreshToken) {
		validateRefreshToken(refreshToken);
		Member member = memberService.findMemberByRefreshToken(refreshToken);
		Date accessTokenExpireTime = jwtTokenProvider.createAccessTokenExpireTime();
		String accessToken =
				jwtTokenProvider.createAccessToken(String.valueOf(member.getId()), member.getRole(), accessTokenExpireTime);
		return TokenRefreshResponse.builder()
				.grantType(GrantType.BEARER.getType())
				.accessToken(accessToken)
				.accessTokenExpireTime(DateTimeUtils.convertToLocalDateTime(accessTokenExpireTime))
				.build();
	}

	private void validateRefreshToken(String refreshToken) {
		boolean validateToken = jwtTokenProvider.validateRefreshToken(refreshToken);
		if (!validateToken) {
			throw new AuthenticationException(ErrorCode.INVALID_REFRESH_TOKEN);
		}
	}

```

Refresh Token에 대한 유효성 검사를 해주고, 해당 Refresh Token으로 회원을 조회한다. 그 후 그 회원 정보로 Access Token을 만들어 리턴한다. 

#### MemberService

```java
	public Member findMemberByRefreshToken(String refreshToken) {
		Member member = memberRepository
				.findByRefreshToken(refreshToken)
				.orElseThrow(() -> new AuthenticationException(ErrorCode.NOT_FOUND_REFRESH_TOKEN));
		LocalDateTime tokenExpirationTime = member.getTokenExpirationTime();
		if (tokenExpirationTime.isBefore(LocalDateTime.now())) {
			throw new AuthenticationException(ErrorCode.EXPIRED_REFRESH_TOKEN);
		}

		return member;
	}

```

Refresh Token으로 회원을 조회할 때, DB에 저장된 Refresh Token의 만료시간도 체크한다. 토큰이 만료되었을 때는 예외를 내보낸다.

### 내 정보 조회

인증 헤더에 담긴 액세스 토큰을 바탕으로 현재 로그인한 회원의 정보를 조회한다. 이번 프로젝트에서는 Custom ArgumentResolver와 @Annotation을 사용했다.

#### @SignInMember

```java

@Target(ElementType.PARAMETER)
@Retention(RetentionPolicy.RUNTIME)
public @interface SignInMember {
}

```

파라미터에서만 사용할 수 있는 애노테이션이다.

#### SignInMemberDto

```java
@Getter @Builder
public class SignInMemberDto {
	private Long memberId;
	private MemberRole role;
}

```

토큰에서 불러온 회원 정보를 담은 DTO이다.

#### SignInMemberArgumentResolver

```java
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
		String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
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

```
SignInMemberArgumentResolver의 기능은 두 가지다.

1. @SignInMember 애노테이션이 파라미터에 붙어있는지 && 해당 파라미터에 SignMemberDto 타입을 할당할 수 있는지를 따져 해당 ArgumentResolver를 적용할 수 있는 파라미터인지 체크한다.
2. 1.을 통과했을 때, access token을 파싱하여 SignMemberDto에 담아 반환한다.

#### WebMvcConfig

```java

@RequiredArgsConstructor
@Configuration
public class WebMvcConfig implements WebMvcConfigurer {

	private final SignInMemberArgumentResolver signInMemberArgumentResolver;
    
    ...

	@Override
	public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
		resolvers.add(signInMemberArgumentResolver);
	}

	...
}

```

위의 SignInMemberArgumentResolver을 등록해준다.

### 로그아웃

인증 헤더의 Access Token으로 회원 정보를 받아서 

1. 해당 회원 테이블에 저장된 Refresh Token 관련 정보를 삭제하고,
2. Refresh Token Cookie를 만료시킨다.

#### AuthController

```java
	@PostMapping("/sign-out")
	public ResponseEntity<Void> signOut(@SignInMember SignInMemberDto signInMemberDto) {

		authService.signOut(signInMemberDto.getMemberId());

		ResponseCookie signOutCookie = refreshTokenCookieUtils.generateSignOutCookie();

		return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, signOutCookie.toString()).build();
	}

```

#### RefreshTokenCookieUtils

```java

@RequiredArgsConstructor
@Component
public class RefreshTokenCookieUtils {
	private final OAuth2Config oAuth2Config;

	...

	public ResponseCookie generateSignOutCookie() {
		return CookieUtils
				.generateResponseCookie(
						oAuth2Config.getAuth().getRefreshCookieKey(),
						"",
						1
				);
	}
}

```

기존 Refresh Token Cookie의 키 값과 똑같은 쿠키를 만들고, value 값을 빈 값으로, maxAge를 1초로 주어 Refresh Token Cookie를 만료한다.

### 회원탈퇴

회원 탈퇴에서 인증 헤더의 Access Token 을 이용하여 현재 로그인한 사용자가 자신을 탈퇴하는 것과 더불어 관리자 권한을 가진 회원이 다른 회원을 탈퇴시키는 기능까지 추가하고자 했다. 

#### MemberController

```java

@RequiredArgsConstructor
@RequestMapping("/api/members")
@RestController
public class MemberController {

	private final MemberService memberService;
	private final RefreshTokenCookieUtils refreshTokenCookieUtils;

	@PreAuthorize("@memberGuard.check(#id)")
	@DeleteMapping("/{id}")
	public ResponseEntity<Void> withdrawMember(@PathVariable Long id, @SignInMember SignInMemberDto signInMemberDto) {
		//회원 삭제
		memberService.withdrawMember(id);

		//본인이라면 refresh token cookie도 삭제
		if (isOwnerMember(id, signInMemberDto.getMemberId())) {
			ResponseCookie signOutCookie = refreshTokenCookieUtils.generateSignOutCookie();
			return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, signOutCookie.toString()).build();
		}

		return ResponseEntity.ok().build();
	}

	private boolean isOwnerMember(Long memberId, Long signInMemberId) {
		return signInMemberId.equals(memberId);
	}

}

```

@PreAuthorize와 MemberGuard 를 이용해서 로그인한 회원과 대상 회원이 동일한지, 관리자 회원인지 체크하고, 회원을 삭제한다. 만약 로그인했던 회원이라면 Refresh Token Cookie도 만료시킨다.

#### Guard

```java

public abstract class Guard {
	public final boolean check(Long id) {
		return hasRole(getMemberRoles()) || isResourceOwner(id);
	}

	abstract protected List<MemberRole> getMemberRoles();

	abstract protected boolean isResourceOwner(Long id);

	private boolean hasRole(List<MemberRole> memberRoles) {
		Set<MemberRole> result = AuthHelper
				.extractMemberRoles()
				.stream()
				.filter(x -> memberRoles.stream().anyMatch(y -> x.getRole().equals(y.getRole())))
				.collect(Collectors.toSet());
		return !result.isEmpty();
	}

}

```

#### MemberGuard

```java

@RequiredArgsConstructor
@Component
public class MemberGuard extends Guard {
	private final List<MemberRole> memberRoles = List.of(MemberRole.ADMIN);
	@Override
	protected List<MemberRole> getMemberRoles() {
		return memberRoles;
	}

	@Override
	protected boolean isResourceOwner(Long id) {
		return id.equals(AuthHelper.extractMemberId());
	}
}

```

Guard라는 개념은 [해당 링크](https://kukekyakya.tistory.com/567?category=1025994)를 보고 [NestJS](https://docs.nestjs.com/guards)가 생각나서 좋다고 생각해 적용해보았다. 공통 기능은 추상 클래스 Guard로 분리하고, 각 용도에 맞게 Guard를 상속해 구현하는 방식을 취한다.

### 공통

#### 전역 예외 처리

**GlobalExceptionHandler (BEFORE)**

```java
@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

	...

	/**
	 * BusinessA 예외 처리
	 */
	@ExceptionHandler(BusinessAException.class)
	protected ResponseEntity<ErrorResponse> handleBusinessAException(BusinessAException e) {
		log.error("BusinessAException", e);
		ErrorResponse errorResponse = ErrorResponse.of(e.getErrorCode().getErrorCode(), e.getMessage());
		return ResponseEntity.status(e.getErrorCode().getHttpStatus()).body(errorResponse);
	}
    
    /**
	 * BusinessB 예외 처리
	 */
	@ExceptionHandler(BusinessBException.class)
	protected ResponseEntity<ErrorResponse> handleBusinessAException(BusinessBException e) {
		log.error("BusinessBException", e);
		ErrorResponse errorResponse = ErrorResponse.of(e.getErrorCode().getErrorCode(), e.getMessage());
		return ResponseEntity.status(e.getErrorCode().getHttpStatus()).body(errorResponse);
	}

	...
}

```

기존에 프로젝트를 진행할 때는 비즈니스 로직 처리 중 발생하는 모든 예외 상황에 각각 대응하는 커스텀 예외를 만들고 + @RestControllerAdvice 를 사용하여 처리해왔다. 매번 새로운 예외를 생성하는 게 번거롭다고 느끼던 중, [custom exception을 언제 써야 할까?](https://tecoble.techcourse.co.kr/post/2020-08-17-custom-exception/) 라는 글을 보고 전역 예외 처리에 대한 고민이 많아졌다. 커스텀 예외를 사용해서 해당 예외를 낸 의도를 명확하게 하고 싶은 생각은 여전했지만, 그런 의도에 비해 예외를 추가하는 비용이 더 크다고 생각했던 와중, [인프런 강의](https://www.inflearn.com/course/%EC%8A%A4%ED%94%84%EB%A7%81%EB%B6%80%ED%8A%B8-api-%ED%85%9C%ED%94%8C%EB%A6%BF) 를 보고 이거다 싶어 적용해봤다. 

**BusinessException**

![BusinessException Diagram](https://velog.velcdn.com/images/y2gcoder/post/ca5e504c-00e4-4fce-9abe-5b43c87f7733/image.png)

**GlobalExceptionHandler (AFTER)**

```java
@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

	...

	/**
	 * 비즈니스 로직 실행 중 예외
	 */
	@ExceptionHandler(BusinessException.class)
	protected ResponseEntity<ErrorResponse> handleBusinessException(BusinessException e) {
		log.error("BusinessException", e);
		ErrorResponse errorResponse = ErrorResponse.of(e.getErrorCode().getErrorCode(), e.getMessage());
		return ResponseEntity.status(e.getErrorCode().getHttpStatus()).body(errorResponse);
	}

	...
}

```

상속을 이용해서 모든 비즈니스 로직에서 발생하는 커스텀 예외의 부모인 BusinessException을 만드는 것이다. 이렇게 함으로써 비즈니스 로직을 변경하거나 추가할 때마다, 필요하면 BusinessException을 상속해 새로운 Exception을 만들어도 공통 예외처리를 담당하는 GlobalExceptionHandler에서는 BusinessException에 대한 예외 처리만 핸들링해주게 되어 예외 처리가 훨씬 편해졌다. (상속은 자바 기본 문법인데 이를 적용할 생각을 못했다는 것에 잠시 현타가 오기는 했다.)


#### Properties 설정값들을 Immutable한 자바 객체로 변환

알다시피 설정해둔 프로퍼티를 스프링 빈에서 사용하고 싶으면 @Value를 이용하는 방법도 있지만, 프로퍼티 바인딩을 통해 자바 객체에 담아 사용할 수도 있다. 보통 설정값을 바인딩한 객체는 변하지 않기 때문에, Spring Boot 2.2.0부터 추가된 [@ConstructorBinding](https://docs.spring.io/spring-boot/docs/current/api/org/springframework/boot/context/properties/ConstructorBinding.html)을 사용해서 Immutable한 객체로 만들었다.

**OAuth2Config, PropertiesConfiguration**

```java

@Validated
@Getter
@RequiredArgsConstructor
@ConstructorBinding
@ConfigurationProperties(prefix = "app")
public final class OAuth2Config {
	@Valid
	private final Auth auth;
	@Valid
	private final OAuth2 oAuth2;

	@Getter
	@RequiredArgsConstructor
	public static final class Auth {
		@NotBlank
		private final String tokenSecret;
		@NotBlank
		private final String refreshCookieKey;
		@Positive
		private final long accessTokenValidityInMs;
		@Positive
		private final long refreshTokenValidityInMs;
	}

	@Getter
	@RequiredArgsConstructor
	public static final class OAuth2 {
		@NotEmpty
		private final List<@URL String> authorizedRedirectUris;
	}

}

//------------------------------------------------------------//

@EnableConfigurationProperties(value = {OAuth2Config.class})
@Configuration
public class PropertiesConfiguration {
}

```

@ConstructBinding을 사용하면 기존의 setter를 통한 바인딩이 아니라 생성자를 통한 바인딩이 가능하기 때문에 @Setter를 다 제거했다. 또한 설정값들에 대한 Validation도 추가해주었다.
기존 설정과 또 다른 점은 해당 설정값을 바인딩한 클래스를 빈으로 등록해주기 위해 따로 @EnableConfigurationProperties를 사용해야 한다는 점이었다. 

#### Spring Rest Docs를 사용한 API 문서화

평소에 프로젝트를 만들 때, API 문서화를 위해 Swagger(OpenAPI)를 애용해왔다. 설정과 애노테이션을 추가하면 바로 동적인 API 문서를 만들어준다는 점이 매력적이었기 때문이다. 하지만 본 프로젝트에서는 아래의 두 가지 이유로 Spring Rest Docs를 채택했다.

- Swagger를 사용했을 때, 실제 코드에 너무 많은 애노테이션이 침투해서 애플리케이션 코드에 대한 분석이 어려웠기 때문이다. 실제 코드는 3~4줄인데, 문서화를 위해 애노테이션을 붙이다 보면 줄길이가 4~5배로 늘어나고 있었다. API 문서를 제공하려다 실제 코드 분석이 더 어려워지는 아이러니한 상황이 발생하고 있어, 이번에는 실제 코드에 영향을 거의 주지 않는 Spring Rest Docs를 사용해보고자 했다.
- Spring Rest Docs는 테스트 코드 기반으로 작성하는 API 문서이기 때문이다. 전 회사에서의 모든 프로젝트의 모든 테스트는 실제로 개발 서버에 배포하여 마치 사용자처럼 UI 화면을 보고 값을 입력하거나 버튼을 클릭하여 진행하는 UI 테스트가 테스트의 전부였다. 테스트를 위해 필요한 비용, 시간이 너무 많이 들었고, 예상치 못한 버그에 대한 대응이 너무 느렸다. 이런 경험들  개인적으로 진행하는 프로젝트는 단위 테스트든 E2E테스트든 테스트 코드를 꼭 작성하기로 마음먹었다. 그러니 Spring Rest Docs를 추가해서 강제로 E2E 테스트를 추가하고 싶었다. 

**HealthCheckControllerE2ETest**

```java

@AutoConfigureRestDocs(uriScheme = "https", uriHost = "y2gcoder.com", uriPort = 443)
@ExtendWith(RestDocumentationExtension.class)
@AutoConfigureMockMvc
@SpringBootTest
class HealthCheckControllerE2ETest {

	@Autowired
	private MockMvc mockMvc;

	@Test
	@DisplayName("Health Check: 성공")
	void whenGetApiHealth_thenHealthOkActiveProfilesTest() throws Exception {
		//given
		//when
		ResultActions resultActions = this.mockMvc.perform(
				RestDocumentationRequestBuilders.get("/api/health")
						.accept(MediaType.APPLICATION_JSON)
		);
		//then
		resultActions.andExpect(status().isOk())
				.andDo(
						document(
								"health-check",
								responseFields(
										fieldWithPath("health").description("server health status"),
										fieldWithPath("activeProfiles").description("server active profiles")
								)
						)
				);
	}
}

```

**API 문서(예시)**
![Spring Rest Docs API 문서](https://velog.velcdn.com/images/y2gcoder/post/948abf75-7bd8-44b7-bea6-63cd3f2dd6f7/image.png)


---

# 피드백

## 아쉬운 점

### github 로그인 시 이슈

현재 템플릿은 OAuth2 Provider로 Google과 Github를 이용하고 있다. 문제는 OAuth2 토큰 발급 시 github에서 필요한 유저 정보를 다 받아오게끔 설정했음에도 불구하고, Github로 로그인을 시도할 때마다 email을 받아오지 못하는 것이었다. [검색](https://stackoverflow.com/questions/35373995/github-user-email-is-null-despite-useremail-scope)해보니 Github는 사용자가 email을 공개하지 않으면 OAuth2 로그인 시 보내는 요청에 대한 응답에서 email 값을 null로 보내는 것이다. 일단 현재 단계에서는 이메일이 없을 때, 해당 이메일 자리에 github ID를 대입하는 방식으로 처리했다. 이메일을 불러오지 못했을 때, github api를 이용해서 이메일을 조회하는 요청을 다시 보내 이메일을 불러오는 것이 가능한지 검토해보고 적용해봐야겠다.

### 회원 정보 관련 기능 필요

소셜 로그인을 통한 회원가입이나, 아이디/비밀번호를 통한 회원가입을 진행하고 나면 더이상 클라이언트 쪽에서 회원 정보를 입력할 수 있는 방법이 없다. 장기적으로 봤을 때는 회원 정보 입력, 회원 정보 수정과 관련한 기능을 추가하고 클라이언트에 제공해야 한다.

### Refresh Token 저장 위치에 대한 고민

앞서 Refresh Token의 저장 위치에 대하여 논하긴 했지만, 좀 더 유연한 설계를 위해서는 Refresh Token에 대한 다른 저장소를 찾아볼 필요가 있다. Refresh Token을 쿠키에 저장하는 현재 방식은 해당 템플릿으로 만든 어플리케이션은 무조건 웹 관련일 수밖에 없다. 좀 더 유연하게 사용할 수 있는 템플릿으로 만들고 싶기 때문에 Refresh Token을 저장할 수 있는 다른 위치를 고민해봐야겠다.

## 마치며

![러닝](https://velog.velcdn.com/images/y2gcoder/post/79c72012-17f0-4b5a-8d40-4f5f49942195/image.png)

퇴사 후 그저 건강을 지키기 위해 시작했던 러닝이 2개월 째 이어지고 있다. 평소에 유산소 운동을 좋아하지 않아 건강이라는 이유만으로 꾸준히 이어갈 수 있을까 걱정했지만, 지금은 원래 목적인 건강 증진 뿐만 아니라 스트레스 해소, 러닝 코스에 있던 집 앞 풍경에 대한 감상까지 더해지면서 러닝을 시작하길 잘했다고 생각하고 있다. 마찬가지로 템플릿을 만든 이유는 시작 부분에 언급했던 것처럼 반복을 줄이기 위해서였지만, 템플릿을 만드는 과정에서 템플릿을 보완하는 과정에서 새로 공부하고 공부한 것을 적용해 더 나아진 코드를 보며 보람을 느끼면서 재미를 느꼈다. 

이제 템플릿을 좀 더 보완하고, 보완된 템플릿을 통해 토이 프로젝트를 하나 만들어볼 계획이다. 먼저 github 로그인 이슈를 해결하여 템플릿을 보완하고, 토이 프로젝트에서는 서버 단 뿐만 아니라 해당 서버와 통신할 프론트 엔드 단도 만들어 배포까지 진행해볼 계획이다. 

---

# References

[인프런 - 생산성을 향상시키는 스프링부트 기반의 API 템플릿 프로젝트 구현](https://www.inflearn.com/course/%EC%8A%A4%ED%94%84%EB%A7%81%EB%B6%80%ED%8A%B8-api-%ED%85%9C%ED%94%8C%EB%A6%BF)

[https://europani.github.io/spring/2022/01/15/036-oauth2-jwt.html#h-authservice](https://europani.github.io/spring/2022/01/15/036-oauth2-jwt.html#h-authservice)

[https://mizzlena.tistory.com/52](https://mizzlena.tistory.com/52)

[https://kukekyakya.tistory.com/567?category=1025994](https://kukekyakya.tistory.com/567?category=1025994)
