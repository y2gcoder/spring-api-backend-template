package com.y2gcoder.app.api.health.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.y2gcoder.app.api.health.dto.HealthCheckResponseDto;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.env.Environment;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doReturn;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
class HealthCheckControllerTest {

	@InjectMocks
	private HealthCheckController healthCheckController;

	@Mock
	private Environment environment;

	private MockMvc mockMvc;
	private ObjectMapper objectMapper;

	@BeforeEach
	public void beforeEach() {
		mockMvc = MockMvcBuilders.standaloneSetup(healthCheckController).build();
		objectMapper = new ObjectMapper();
	}

	@Test
	@DisplayName("HealthCheckController(단위): Health Check, 성공")
	void whenHealthCheck_thenReturnHealthCheckResponseDto() throws Exception {
		//given
		String[] profileArrays = {"test"};
		doReturn(profileArrays).when(environment).getActiveProfiles();
		//when
		ResultActions resultActions = mockMvc.perform(
				MockMvcRequestBuilders.get("/api/health")
						.contentType(MediaType.APPLICATION_JSON)
		);
		//then
		MvcResult mvcResult = resultActions.andExpect(status().isOk()).andReturn();
		HealthCheckResponseDto result = objectMapper
				.readValue(mvcResult.getResponse().getContentAsString(), HealthCheckResponseDto.class);
		assertThat(result.getHealth()).isEqualTo("ok");
		assertThat(result.getActiveProfiles()).isNotEmpty();
		assertThat(result.getActiveProfiles()).containsOnly("test");

	}
}