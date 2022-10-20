package com.y2gcoder.app.global.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.y2gcoder.app.global.error.ErrorResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
@Component
public class CustomAuthenticationEntrypoint implements AuthenticationEntryPoint {
	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
		log.error("AuthenticationException", authException);
		response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		response.setContentType(MediaType.APPLICATION_JSON.toString());
		response.setCharacterEncoding("utf-8");
		ObjectMapper objectMapper = new ObjectMapper();
		ErrorResponse errorResponse = ErrorResponse.of(HttpStatus.UNAUTHORIZED.toString(), authException.getMessage());

		String errorResponseJson = objectMapper.writeValueAsString(errorResponse);
		response.getWriter().println(errorResponseJson);
	}
}
