package com.junsang.member.security.oauth;

import com.junsang.member.entity.Members;
import com.junsang.member.entity.enumType.RoleType;
import lombok.Builder;
import lombok.Getter;

import java.time.LocalDateTime;
import java.util.Map;


@Getter
@Builder
public class OAuth2AttributesDTO {
    private Map<String, Object> attributes;
    private String nameAttributeKey;
    private String name;
    private String email;
    private String picture;
    private String socialType;
    private String accessToken;
    private String refreshToken;

    /**
     * OAuth2User 객체가 반환하는 사용자 정보는 Map 형식이라 값 하나하나를 변환하기 위함
     *
     * @param registrationId            현재 서비스 구분 코드
     * @param userNameAttributeName     OAuth 2.0 키가 되는 필드
     * @param attributes                유저 정보
     * @param accessToken
     * @param refreshToken
     * @return
     */
    public static OAuth2AttributesDTO of(String registrationId, String userNameAttributeName, Map<String, Object> attributes, String accessToken, String refreshToken) {

        // 네이버
        if ("naver".equals(registrationId)) {
            Map<String, Object> response = (Map<String, Object>) attributes.get("response");

            return OAuth2AttributesDTO.builder()
                    .name((String) response.get("name"))
                    .email((String) response.get("email"))
                    .picture((String) response.get("profile_image"))
                    .socialType(registrationId)
                    .attributes(response)
                    .nameAttributeKey(userNameAttributeName)
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .build();
        }

        // 카카오
        if ("kakao".equals(registrationId)) {
            Map<String, Object> kakaoAccount = (Map<String, Object>) attributes.get("kakao_account");
            Map<String, Object> profile = (Map<String, Object>) kakaoAccount.get("profile");

            return OAuth2AttributesDTO.builder()
                    .name((String) profile.get("nickname"))
                    .email((String) "카카오는_이메일_안줌ㅠ")
                    .picture((String) profile.get("thumbnail_image_url"))
                    .socialType(registrationId)
                    .attributes(attributes)
                    .nameAttributeKey(userNameAttributeName)
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .build();
        }

        // 구글
        if ("google".equals(registrationId)) {
            return OAuth2AttributesDTO
                    .builder()
                    .name((String) attributes.get("name"))          // attributes -> name
                    .email((String) attributes.get("email"))        // attributes -> email
                    .picture((String) attributes.get("picture"))    // attributes -> picture
                    .attributes(attributes)                         // attributes -> sub, name, given_name, family_name, picture, email, email_verified, locale
                    .socialType(registrationId)                     // 현재 서비스 구분 코드 -> google
                    .nameAttributeKey(userNameAttributeName)        // OAuth 2.0 키가 되는 필드 -> sub
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .build();
        }

        return null;
    }


    /**
     * 첫 가입자일 경우 실행
     * - default 권한 : 브론즈
     */
    public Members toEntity() {
        return Members.builder()
                .username(name)
                .email(email)
                .joinCd("02")
                .lastLoginDt(LocalDateTime.now())
                .roleType(RoleType.BRONZE)
                .build();
    }
}