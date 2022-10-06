package com.y2gcoder.app.api.health.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.List;

@Getter
@AllArgsConstructor
public class HealthCheckResponseDto {
	private String health;
	private List<String> activeProfiles;
}
