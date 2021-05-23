package com.junsang.member.security.oauth;

import com.joonsang.example.CommunityExam.entity.Account;
import com.joonsang.example.CommunityExam.repository.AccountRepository;
import com.joonsang.example.CommunityExam.security.methodOAuth2.dto.OAuthAttributes;
import com.joonsang.example.CommunityExam.security.methodOAuth2.dto.SessionUser;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpSession;
import java.util.Collections;

/**
 * 로그인 성공 후, 리소스 서버에서 가져온 사용자 정보(name, email, picture 등) 들을 기반으로 가입/수정/세션 저장의 기능 지원
 */
@RequiredArgsConstructor
@Service
public class CustomOAuthUserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final AccountRepository accountRepository;
    private final HttpSession httpSession;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        // OAuth2UserService 인스턴스 생성
        OAuth2UserService delegate = new DefaultOAuth2UserService();

        // OAuth2UserService 로 가져온 유저 정보
        OAuth2User oAuth2User = delegate.loadUser(userRequest);

        // 현재 로그인 진행 중인 서비스를 구분하는 코드 (google/facebook/kakao 등)
        String registrationId = userRequest.getClientRegistration().getRegistrationId();

        // OAuth 2 로그인 진행 시, 키가 되는 필드 값 (PK)
        String userNameAttributeName = userRequest.getClientRegistration().getProviderDetails()
                .getUserInfoEndpoint().getUserNameAttributeName();

        // OAuth2UserService 로 가져온 유저 정보를 속성 DTO 에 담음
        OAuthAttributes attributes = OAuthAttributes.of(registrationId, userNameAttributeName, oAuth2User.getAttributes());

        // 저장 또는 수정, (DB 에 정보가 없으면 저장)
        Account account = saveOrUpdate(attributes);

        // OAuth2UserService 로 가져온 유저 정보를 세션 DTO 에 담음 (노트 OAuth2 2-1 참고)
        httpSession.setAttribute("user", new SessionUser(account));

        return new DefaultOAuth2User(
                Collections.singleton(new SimpleGrantedAuthority(account.getRoleType().getRoleType())),
                attributes.getAttributes(),             // name 등 속성
                attributes.getNameAttributeKey());      // PK
    }

    /**
     * 사용자 정보가 업데이트 되었을 경우, update 기능 구현
     * - 이름 또는 프로필 사진이 변경 되면 User 엔티티도 반영
     */
    private Account saveOrUpdate(OAuthAttributes attributes) {
        try {
            accountRepository.findByEmail(attributes.getEmail()).getEmail();
        } catch (NullPointerException e) {
            Account newAccount = attributes.toEntity();
            return accountRepository.save(newAccount);
        }

        Account a = attributes.toEntity();
        return a;
    }
}