package com.y2gcoder.app.global.config.security;

import com.y2gcoder.app.global.config.jwt.filter.JwtAuthenticationFilter;
import com.y2gcoder.app.global.config.security.handler.JwtAccessDeniedHandler;
import com.y2gcoder.app.global.config.security.handler.JwtAuthenticationEntrypoint;
import com.y2gcoder.app.global.config.security.handler.OAuth2AuthenticationFailureHandler;
import com.y2gcoder.app.global.config.security.handler.OAuth2AuthenticationSuccessHandler;
import com.y2gcoder.app.global.config.security.repository.CustomAuthorizationRequestRepository;
import com.y2gcoder.app.global.config.security.service.CustomOAuth2UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Slf4j
@RequiredArgsConstructor
@EnableGlobalMethodSecurity(
		securedEnabled = true
		, prePostEnabled = true
//		, jsr250Enabled = true
)
@EnableWebSecurity
@Configuration
public class SecurityConfig {
	private final CustomAuthorizationRequestRepository customAuthorizationRequestRepository;
	private final CustomOAuth2UserService customOAuth2UserService;
	private final OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler;
	private final OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;
	private final JwtAuthenticationFilter jwtAuthenticationFilter;
	private final JwtAuthenticationEntrypoint jwtAuthenticationEntrypoint;
	private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http.authorizeRequests()
				.antMatchers("/login/oauth2/**").permitAll()
				.antMatchers("/api/admin/**").hasRole("ADMIN")
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
				.authenticationEntryPoint(jwtAuthenticationEntrypoint)
				.accessDeniedHandler(jwtAccessDeniedHandler);

		http.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

		return http.build();
	}
}
