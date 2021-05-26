package com.junsang.member.security.oauth;

import com.junsang.member.dto.ReqLogin;
import com.junsang.member.entity.Members;
import com.junsang.member.repository.MemberRepository;
import com.junsang.member.security.jwt.JwtProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpSession;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * 로그인 성공 후, 리소스 서버에서 가져온 사용자 정보(name, email, picture 등) 들을 기반으로 가입/수정/세션 저장의 기능 지원
 */
@RequiredArgsConstructor
@Service
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final MemberRepository memberRepository;


    @Autowired
    private JwtProvider jwtProvider;


    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        // OAuth2UserService 인스턴스 생성
        OAuth2UserService delegate = new DefaultOAuth2UserService();

        // 현재 서비스 구분 코드 (google/facebook/kakao 등)
        String curRegistrationCode = userRequest
                .getClientRegistration()
                .getRegistrationId();

        // OAuth2UserService 로 가져온 유저 정보
        OAuth2User oAuth2User = delegate.loadUser(userRequest);

        // OAuth 2 로그인 진행 시, 키가 되는 필드 값 (PK) - google: sub
        String userNameAttributeName = userRequest
                .getClientRegistration()
                .getProviderDetails()
                .getUserInfoEndpoint()
                .getUserNameAttributeName();

        /** Token 생성 **/
        // 토큰 생성
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
                "A"             // principal   - 이메일
                , "B"        // credentials - 패스워드
                , new ArrayList<>()
        );
        Authentication auth = token;
        String accessToken = jwtProvider.createToken(auth);
        String refreshToken = jwtProvider.createToken(auth);

        // OAuth2UserService 로 가져온 유저 정보를 속성 DTO 에 담음
        OAuth2AttributesDTO attributes = OAuth2AttributesDTO.of(
                curRegistrationCode,            // 현재 서비스 구분 코드
                userNameAttributeName,          // OAuth 2.0 키가 되는 필드 (Google: sub / Naver: respone / kakao: id)
                oAuth2User.getAttributes(),    // 유저 정보
                accessToken,
                refreshToken);

        // 저장 또는 수정, (DB 에 정보가 없으면 저장)
        Members member = saveOrUpdate(attributes);
        Map<String, Object> attributes1 = attributes.getAttributes();
        Map<String, Object> attributes2 = new HashMap<>();
        for(String key : attributes1.keySet() ){
            attributes2.put(key, attributes1.get(key));
        }


        attributes2.put("myAccessToken", accessToken);
        attributes2.put("myRefreshToken", refreshToken);

        return new DefaultOAuth2User(
                Collections.singleton(new SimpleGrantedAuthority(member.getRoleType())),
                attributes2,             // 속성
                attributes.getNameAttributeKey());      // PK
    }

    /**
     * 사용자 정보가 업데이트 되었을 경우, update 기능 구현
     * - 이름 또는 프로필 사진이 변경 되면 User 엔티티도 반영
     */
    private Members saveOrUpdate(OAuth2AttributesDTO attributes) {

        Members member = memberRepository.findByEmail(attributes.getEmail())
                .map(entity -> entity.update(attributes.getName(), attributes.getPicture()))
                .orElse(attributes.toEntity());

        // 레디스에 저장장

       return memberRepository.save(member);
    }
}