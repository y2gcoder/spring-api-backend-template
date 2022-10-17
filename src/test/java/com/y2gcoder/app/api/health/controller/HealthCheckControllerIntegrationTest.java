package com.y2gcoder.app.api.health.controller;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.restdocs.AutoConfigureRestDocs;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.restdocs.RestDocumentationExtension;
import org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.payload.PayloadDocumentation.fieldWithPath;
import static org.springframework.restdocs.payload.PayloadDocumentation.responseFields;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@AutoConfigureRestDocs(uriScheme = "https", uriHost = "y2gcoder.com", uriPort = 443)
@ExtendWith(RestDocumentationExtension.class)
@AutoConfigureMockMvc
@SpringBootTest
class HealthCheckControllerIntegrationTest {

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