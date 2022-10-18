package com.y2gcoder.app.global.config.security;

import com.y2gcoder.app.global.jwt.filter.JwtAuthenticationFilter;
import com.y2gcoder.app.global.security.handler.CustomAccessDeniedHandler;
import com.y2gcoder.app.global.security.handler.CustomAuthenticationEntrypoint;
import com.y2gcoder.app.global.security.handler.OAuth2AuthenticationFailureHandler;
import com.y2gcoder.app.global.security.handler.OAuth2AuthenticationSuccessHandler;
import com.y2gcoder.app.global.security.repository.CustomAuthorizationRequestRepository;
import com.y2gcoder.app.global.security.service.CustomOAuth2UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

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
				.antMatchers("/login/oauth2/**").permitAll()
				.antMatchers(HttpMethod.POST, "/api/auth/refresh", "/api/auth/sign-up", "/api/auth/sign-in").permitAll()
				.antMatchers(HttpMethod.POST, "/api/auth/sign-out").authenticated()
				.antMatchers(HttpMethod.GET, "/api/members/me").authenticated()
				.antMatchers(HttpMethod.DELETE, "/api/members/{id}").authenticated()
				.antMatchers(HttpMethod.GET, "/api/**").permitAll()
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
