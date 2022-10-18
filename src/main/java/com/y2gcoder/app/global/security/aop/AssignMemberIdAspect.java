package com.y2gcoder.app.global.security.aop;

import com.y2gcoder.app.global.security.guard.AuthHelper;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.springframework.stereotype.Component;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Optional;

@Slf4j
@Component
@Aspect
public class AssignMemberIdAspect {

	@Before("@annotation(com.y2gcoder.app.global.security.annotation.AssignMemberId)")
	public void assignMemberId(JoinPoint joinPoint) {
		Arrays.stream(joinPoint.getArgs())
				.forEach(arg ->
						getMethod(arg.getClass(), "setMemberId")
								.ifPresent(setMemberId -> invokeMethod(arg, setMemberId, AuthHelper.extractMemberId())));
	}

	private Optional<Method> getMethod(Class<?> clazz, String methodName) {
		try {
			return Optional.of(clazz.getMethod(methodName, Long.class));
		} catch (NoSuchMethodException e) {
			return Optional.empty();
		}
	}

	private void invokeMethod(Object obj, Method method, Object... args) {
		try {
			method.invoke(obj, args);
		} catch (IllegalAccessException | InvocationTargetException e) {
			throw new RuntimeException(e);
		}
	}
}
