package com.y2gcoder.app.global.security.service;

import com.y2gcoder.app.domain.member.constant.AuthProvider;
import com.y2gcoder.app.domain.member.constant.MemberRole;
import com.y2gcoder.app.domain.member.entity.Member;
import com.y2gcoder.app.domain.member.repository.MemberRepository;
import com.y2gcoder.app.global.security.dto.CustomUserDetails;
import com.y2gcoder.app.global.security.dto.OAuth2AttributeFactory;
import com.y2gcoder.app.global.security.dto.OAuth2Attributes;
import com.y2gcoder.app.global.error.ErrorCode;
import com.y2gcoder.app.global.error.exception.AuthenticationException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Slf4j
@RequiredArgsConstructor
@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {
	private final MemberRepository memberRepository;

	@Override
	public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
		OAuth2User oAuth2User = super.loadUser(userRequest);
		return processOAuth2User(userRequest, oAuth2User);
	}

	private OAuth2User processOAuth2User(OAuth2UserRequest userRequest, OAuth2User oAuth2User) {
		String registrationId = userRequest.getClientRegistration().getRegistrationId();
		OAuth2Attributes oAuth2Attributes = OAuth2AttributeFactory.getOAuth2Attributes(
				registrationId,
				oAuth2User.getAttributes()
		);
		AuthProvider authProvider = AuthProvider.valueOf(registrationId);
		Optional<Member> optionalMember = memberRepository.findByEmail(oAuth2Attributes.getEmail());
		Member member;
		if (optionalMember.isPresent()) {
			member = optionalMember.get();
			if (!member.getProvider().equals(authProvider)) {
				throw new AuthenticationException(ErrorCode.INVALID_AUTH_PROVIDER);
			}
		} else {
			member = registerMember(authProvider, oAuth2Attributes);
		}

		return CustomUserDetails.create(member);
	}

	private Member registerMember(AuthProvider authProvider, OAuth2Attributes oAuth2Attributes) {
		Member member = Member.builder()
				.email(oAuth2Attributes.getEmail())
				.role(MemberRole.USER)
				.nickname(oAuth2Attributes.getName())
				.profile(oAuth2Attributes.getImageUrl())
				.provider(authProvider)
				.build();
		return memberRepository.save(member);
	}


}
