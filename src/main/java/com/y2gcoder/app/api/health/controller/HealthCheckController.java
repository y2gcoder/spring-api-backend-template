package com.y2gcoder.app.api.health.controller;

import com.y2gcoder.app.api.health.dto.HealthCheckResponseDto;
import lombok.RequiredArgsConstructor;
import org.springframework.core.env.Environment;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;

@RequiredArgsConstructor
@RequestMapping("/api")
@RestController
public class HealthCheckController {
	private final Environment environment;

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
