package com.junsang.member.security.oauth;

import lombok.Builder;
import lombok.Getter;

import java.util.Map;


@Getter
public class OAuthAttributes {
    private Map<String, Object> attributes;
    private String nameAttributeKey;
    private String name;
    private String email;
    private String picture;
    private String socialType;

    @Builder
    public OAuthAttributes(Map<String, Object> attributes, String nameAttributeKey, String name, String email, String picture, String socialType) {
        this.attributes = attributes;
        this.nameAttributeKey = nameAttributeKey;
        this.name = name;
        this.email = email;
        this.picture = picture;
        this.socialType = socialType;
    }

    /**
     * OAuth2User 에서 반환하는 사용자 정보는 Map 이라 값 하나하나를 변환해야 하므로 of() 사용
     */
    public static OAuthAttributes of(String registrationId, String userNameAttributeName, Map<String, Object> attributes) {

        if ("naver".equals(registrationId)) {
            Map<String, Object> response = (Map<String, Object>) attributes.get("response");

            return OAuthAttributes.builder()
                    .name((String) response.get("name"))
                    .email((String) response.get("email"))
                    .picture((String) response.get("profile_image"))
                    .socialType(registrationId)
                    .attributes(response)
                    .nameAttributeKey("id")
                    .build();
        }

        if ("google".equals(registrationId)) {
            return OAuthAttributes.builder()
                    .name((String) attributes.get("name"))
                    .email((String) attributes.get("email"))
                    .picture((String) attributes.get("picture"))
                    .socialType(registrationId)
                    .attributes(attributes)
                    .nameAttributeKey(userNameAttributeName)
                    .build();
        }

        return null;
    }


    /**
     * User 엔티티 생성
     * - 초기 가입은 GUEST 권한 부여
     */
    public Account toEntity() {
        roleType st = null;
        switch (socialType) {
            case "facebook":
                st = FACEBOOK;
                break;
            case "google":
                st = GOOGLE;
                break;
            case "kakao":
                st = KAKAO;
                break;
            case "naver":
                st = NAVER;
                break;
            default:
                break;
        }

        return Account.builder()
                .nickname(name)
                .email(email)
                .picture(picture)
                .roleType(st)
                .build();
    }
}