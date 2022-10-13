package com.y2gcoder.app.global.util;

import com.y2gcoder.app.global.config.jwt.constant.GrantType;
import org.springframework.util.StringUtils;

public class JwtUtils {
	public static String getTokenFromRequest(String authorizationHeader) {
		if (StringUtils.hasText(authorizationHeader) && authorizationHeader.startsWith(GrantType.BEARER.getType())) {
			return authorizationHeader.substring(7);
		}
		return null;
	}
}
