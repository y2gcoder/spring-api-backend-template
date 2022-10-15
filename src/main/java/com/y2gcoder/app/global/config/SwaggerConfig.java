package com.y2gcoder.app.global.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.service.*;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spi.service.contexts.SecurityContext;
import springfox.documentation.spring.web.plugins.Docket;

import java.util.Collections;
import java.util.List;

@Configuration
public class SwaggerConfig {
	@Bean
	public Docket api() {
		return new Docket(DocumentationType.OAS_30)
				.select() //ApiSelectorBuilder 생성
				.apis(RequestHandlerSelectors.basePackage("com.y2gcoder.app.api"))
				.paths(PathSelectors.ant("/api/**"))  //path 조건에 따라서 APi 문서화 TODO API 경로 수정
				.build()
				.apiInfo(apiInfo())  //API 문서에 대한 정보 추가
				.useDefaultResponseMessages(false)
				.securityContexts(Collections.singletonList(securityContext()))
				.securitySchemes(List.of(apiKey()))
				;
	}

	private ApiInfo apiInfo() {
		return new ApiInfoBuilder()
				.title("YG API Backend Template") //TODO 수정 필요
				.description("양갱의 Spring Boot API Template API 문서입니다.") //TODO 수정 필요
				.contact(new Contact("양영근", "y2gcoder.com", "y2gcoder@gmail.com"))
				.version("1.0.0")
				.build();
	}

	private SecurityContext securityContext() {
		return SecurityContext.builder()
				.securityReferences(defaultAuth())
				.build();
	}

	private List<SecurityReference> defaultAuth() {
		AuthorizationScope authorizationScope = new AuthorizationScope("global", "global access");
		AuthorizationScope[] authorizationScopes = new AuthorizationScope[1];
		authorizationScopes[0] = authorizationScope;
		return List.of(new SecurityReference("Authorization", authorizationScopes));
	}

	private ApiKey apiKey() {
		return new ApiKey("Authorization", "Authorization", "header");
	}
}
