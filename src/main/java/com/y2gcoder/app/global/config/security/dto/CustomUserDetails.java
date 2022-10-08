package com.y2gcoder.app.global.config.security.dto;

import com.y2gcoder.app.domain.member.entity.Member;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public class CustomUserDetails implements OAuth2User, UserDetails {

	private Long id;
	private String email;

	private String password;
	private Collection<? extends  GrantedAuthority> authorities;
	private Map<String, Object> attributes;

	public CustomUserDetails(Long id, String email, String password, Collection<? extends GrantedAuthority> authorities) {
		this.id = id;
		this.email = email;
		this.password = password;
		this.authorities = authorities;
	}

	public static CustomUserDetails create(Member member) {
		List<SimpleGrantedAuthority> authorities = Collections
				.singletonList(new SimpleGrantedAuthority(member.getRole().getRole()));
		return new CustomUserDetails(
				member.getId(),
				member.getEmail(),
				member.getPassword(),
				authorities
		);
	}

	public static CustomUserDetails create(Member member, Map<String, Object> attributes) {
		CustomUserDetails customUserDetails = CustomUserDetails.create(member);
		customUserDetails.setAttributes(attributes);
		return customUserDetails;
	}

	public void setAttributes(Map<String, Object> attributes) {
		this.attributes = attributes;
	}

	@Override
	public String getPassword() {
		return password;
	}

	@Override
	public String getUsername() {
		return email;
	}

	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		return true;
	}

	@Override
	public Map<String, Object> getAttributes() {
		return attributes;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return authorities;
	}

	@Override
	public String getName() {
		return String.valueOf(id);
	}
}
