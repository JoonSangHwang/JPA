package com.junsang.member.security.oauth;

import com.junsang.member.dto.ResLogin;
import com.junsang.member.entity.Members;
import com.junsang.member.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.MethodParameter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpSession;

/**
 * 조건에 맞는 경우(=supportsParameter)의 메소드가 있다면, 해당 메소드의 파라미터로 리졸브 !!
 * HandlerMethodArgumentResolver 는 항상 WebMvcConfigurer 의 addArgumentResolvers() 를 통해 추가.
 */
@Component
@RequiredArgsConstructor
public class UserArgumentResolver implements HandlerMethodArgumentResolver {

    @Autowired
    private MemberRepository memberRepository;

    /**
     * HandlerMethodArgumentResolver 인터페이스의 지원 여부 판단
     *
     * - 파라미터에 어노테이션 @SocialUser 인 경우 true
     * - 파라미터 클래스 타입이 User.class 인 경우 true
     * - return true 일 경우, resolveArgument() 실행
     */
    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        boolean isLoginUserAnnotation = parameter.getParameterAnnotation(SocialUser.class) != null;
        boolean isUserClass = Members.class.equals(parameter.getParameterType());
        return isLoginUserAnnotation && isUserClass;
    }

    /**
     * 해당 파라미터 객체에 바인딩(리졸브)
     *
     * 1. 유저 정보를 세션에서 가져옴
     * 2. 없으면 ? 유저정보를 SecurityContextHolder 에서 가져옴
     * 3. 없으면 ? 유저정보를 DB 에서 조회하여 User 객체를 반환 (질문: save 를 할 필요가 있는건가 ?)
     */
    @Override
    public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer mavContainer, NativeWebRequest webRequest, WebDataBinderFactory binderFactory) {
        // 세션 객체를 가져옴
        HttpSession session = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest().getSession();

        // 세션에서 유저 정보를 가져옴
//        SessionUser sessionUser = (SessionUser) session.getAttribute("user");
//        Account account = new Account(sessionUser.getName(), sessionUser.getEmail(), sessionUser.getPicture());

        // User 타입의 객체 생성
//        return getUser(account, session);
        ResLogin login = new ResLogin();
        return login;
    }

    /**
     * User 타입의 객체를 반환하기 위해 유저 정보 조회
     */
//    private Account getUser(Account account, HttpSession session) {
//        // 세션에 정보가 없을 경우...
//        if (account == null) {
//            try {
//                // SecurityContextHolder 에서 OAuth2AuthenticationToken 을 가져옴
//                OAuth2AuthenticationToken authentication
//                        = (OAuth2AuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
//
//                // SecurityContextHolder 에서 가져온 토큰 개인정보를 Map 에 담음
//                Map<String, Object> map = authentication.getPrincipal().getAttributes();
//
//                // SecurityContextHolder 에서 가져온 토큰 정보로 getAuthorizedClientRegistrationId() 을 통해, 인증 된 소셜 미디어를 알 수 있음
//                Account convertAccount = convertUser(authentication.getAuthorizedClientRegistrationId(), map);
//
//                // SecurityContextHolder 에서 가져온 토큰 정보를 User 객체로 변환 후, DB 에서 조회
//                account = accountRepository.findByEmail(convertAccount.getEmail());
//
//                // SecurityContextHolder 에서 찾은 정보가 DB 에 없다면, 저장 !!
//                if (account == null) {
//                    account = accountRepository.save(convertAccount);
//                }
//
//                setRoleIfNotSame(account, authentication, map);
//                session.setAttribute("user", account);
//            } catch (ClassCastException e) {
//                return account;
//            }
//        }
//
//        return account;
//    }

//    private Account convertUser(String authority, Map<String, Object> map) {
//        if(FACEBOOK.equals(authority))
//            return getModernUser(FACEBOOK, map);
//        else if("google".equals(authority))
//            return getModernUser(GOOGLE, map);
//        else if(KAKAO.equals(authority))
//            return getKaKaoUser(map);
//        else
//            return null;
//    }
//
//    private Account getModernUser(roleType roleType, Map<String, Object> map) {
//        return Account.builder()
//                .nickname(String.valueOf(map.get("name")))
//                .email(String.valueOf(map.get("email")))
//                .roleType(roleType)
//                .build();
//    }
//
//    private Account getKaKaoUser(Map<String, Object> map) {
//        Map<String, String> propertyMap = (HashMap<String, String>) map.get("properties");
//        return Account.builder()
//                .nickname(propertyMap.get("nickname"))
//                .email(String.valueOf(map.get("kaccount_email")))
//                .roleType(KAKAO)
//                .build();
//    }

    /**
     * 인증된 토큰이 권한을 가지고 있는지 체크
     *
     * @param account    DB 유저 정보
     * @param auth    SecurityContextHolder 유저 정보
     * @param map     유저 정보
     */
//    private void setRoleIfNotSame(Account account, OAuth2AuthenticationToken auth, Map<String, Object> map) {
//        if (!auth.getAuthorities().contains(new SimpleGrantedAuthority(account.getRoleType().getRoleType()))) {
//            SecurityContextHolder
//                    .getContext()
//                    .setAuthentication(new UsernamePasswordAuthenticationToken(map, "N/A", AuthorityUtils.createAuthorityList(account.getRoleType().getRoleType())));
//        }
//    }
}
