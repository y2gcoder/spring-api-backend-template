package com.y2gcoder.app.api.health.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class HealthCheckResponseDto {
	private String health;
	private List<String> activeProfiles;
}
