package com.y2gcoder.app.api.health.controller;

import com.y2gcoder.app.api.health.dto.HealthCheckResponseDto;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.core.env.Environment;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;

@Tag(name = "health check", description = "서버 상태 체크 API")
@RequiredArgsConstructor
@RequestMapping("/api")
@RestController
public class HealthCheckController {
	private final Environment environment;

	@Tag(name = "health check")
	@Operation(summary = "서버 Health Check API", description = "현재 서버가 정상적으로 기동이 된 상태인지 검사하는 API")
	@GetMapping("/health")
	public ResponseEntity<HealthCheckResponseDto> healthCheck() {
		return ResponseEntity.ok(
				new HealthCheckResponseDto(
						"ok",
						Arrays.asList(environment.getActiveProfiles())
				)
		);
	}
}
