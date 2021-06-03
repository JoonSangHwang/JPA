package com.junsang.member.security.jwt;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * 요청 흐름
 * : Request  ===>  Filter  ===>  DispatcherServlet  ===>  Interceptior  ===>  Controller
 *
 * 이 클래스에서는 OncePerRequestFilter 사용
 * : 필터가 재실행되는 경우를 방지한다.
 * : 요청당 필터는 정확히 1번만 실행 된다.
 *
 * 문제
 * : 처음에 필터가 2번 실행 되었다. 왜?
 * : 스프링 부트를 사용하다 보면 가장 처음으로 만나는 “@ComponentScan"와 “@Component"에 있다. “@SpringBootApplication"는 여러 어노테이션의 묶음이고 그 안에는 “@ComponentScan"가 있어서 빈들을 자동으로 등록해주는 역할을 하게 되는데 필터에 “@Component"가 설정되어 있어 자동으로 등록이 되었고, 두번째 방법인 “@WebFilter + @ServletComponentScan” 조합으로 한번 더 등록되어버린 것이다. 즉, 동일한 필터가 두번 등록된 상황.
 *   “/test” 에서 한번 로깅된건 “@Component” 에 의해 등록된 필터로 인해 urlPattern 이 적용되지 않았으니 한번 로깅이 되고, urlPattern 이 적용된 필터에서는 urlPattern에 맞지 않으니 로깅이 안되는건 당연. 그 다음 “/filtered/test” 은 “@Component” 에 의해 등록된 필터로 한번 로깅, 그다음 “@WebFilter"로 등록된 필터에서 urlPattern에 맞는 url 이다보니 로깅이 되서 총 두번 로깅이 되게 된다.
 *   즉, 모든 url에 필터를 적용 할 것이라면 “@ComponentScan + @Component” 조합으로 해도 될 것 같고, 명시적으로 특정 urlPattern 에만 필터를 적용한다거나 필터의 다양한 설정 (우선순위, 필터이름 등) 을 하게 되는 경우엔 위에서 알려준 “FilterRegistrationBean” 이나 “@WebFilter + @ServletComponentScan"을 사용해서 상황에 맞도록 설정하는게 중요할 것 같다
 */
@Slf4j
public class JwtFilter extends OncePerRequestFilter {

    private static final String AUTHORITIES_ACCESS_TOKEN_HEADER  = "AuthHeader";
    private static final String AUTHORITIES_REFRESH_TOKEN_HEADER = "refreshTokenHeader";

    @Autowired
    private AuthenticationManagerBuilder authenticationManagerBuilder;

    private final JwtProvider jwtProvider;

    public JwtFilter(JwtProvider jwtProvider) {
        this.jwtProvider = jwtProvider;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        /* 요청 헤더에서 Token 정보 추출 */
        Map<String, String>   tokenInfo = getTokenInHeader(request);
        String accessToken  = tokenInfo.get("accessToken");
        String refreshToken = tokenInfo.get("refreshToken");


        /* Access Token & Refresh Token 유효성 검사 */
        boolean isValid = accessTokenValidate(accessToken, refreshToken, request);


        // 정상 토큰
        if (isValid) {
            // 토큰에서 유저 정보를 가져와 Auth 객체를 만듬
            Authentication auth = jwtProvider.getAuthentication(accessToken);

            // 요청으로 들어온 토큰 그대로 담아 반환
            if (request.getAttribute("AccessTokenData") == null)
                request.setAttribute("AccessTokenData", accessToken);

            request.setAttribute("RefreshTokenData", refreshToken);

            // 시큐리티 컨텍스트에 Auth 객체 저장
            SecurityContextHolder.getContext().setAuthentication(auth);
            filterChain.doFilter(request, response);
        }


        /**
         * 비정상 토큰
         * - 토큰이 없는 사용자
         */
        else {

            // 에러


            request.getRequestDispatcher("/api/tokenIssuance").forward(request, response);
        }
    }


    /**
     * 헤더에 포함된 토큰 값 꺼내기
     */
    public Map<String, String> getTokenInHeader(HttpServletRequest request) {
        Map<String, String> tokenInfo = new HashMap();

        // 액세스 토큰 추출
        String bearerAccessToken = request.getHeader(AUTHORITIES_ACCESS_TOKEN_HEADER);
        if (StringUtils.hasText(bearerAccessToken) && bearerAccessToken.startsWith("Bearer "))
            tokenInfo.put("accessToken", bearerAccessToken.substring(7));
        else
            tokenInfo.put("accessToken", null);

        // 리프레시 토큰 추출
        String bearerRefreshToken = request.getHeader(AUTHORITIES_REFRESH_TOKEN_HEADER);
        if (StringUtils.hasText(bearerRefreshToken) && bearerRefreshToken.startsWith("Bearer "))
            tokenInfo.put("refreshToken", bearerRefreshToken.substring(7));
        else
            tokenInfo.put("refreshToken", null);

        return tokenInfo;
    }


    /**
     * 접근 토큰 검증
     *
     * @param accessToken       접근 토큰
     * @param refreshToken      갱신 토큰
     * @param request           요청
     *
     * @return true: 정상 / false: 비정상
     */
    private boolean accessTokenValidate(String accessToken, String refreshToken, HttpServletRequest request) {

        // Access Token 존재하지 않을 경우
        if (!StringUtils.hasText(accessToken))
            return refreshTokenValidate(refreshToken, request);

        // Access Token 유효성 검증
        String validateResult = jwtProvider.validateToken(accessToken);
        if ("EXPIRED_TOKEN".equals(validateResult))     //= 만료된 토큰
            return refreshTokenValidate(refreshToken, request);
        else if (!"".equals(validateResult)) {          //= 비정상 토큰
            request.setAttribute("exception", validateResult);      // 에러
            return false;
        }

        // 토큰 Payload 검증
        if (!jwtProvider.payLoadValid(accessToken, "ACCESS"))
            return false;

        // 토큰의 만료 일자를 확인하여 만기 일자가 가깝다면, 재발급
        if (jwtProvider.isReissued(accessToken))
            return false;

        return true;
    }


    /**
     * 갱신 토큰 검증
     *
     * @param refreshToken      갱신 토큰
     * @param request           요청
     *
     * @return true: 정상 / false: 비정상
     */
    private boolean refreshTokenValidate(String refreshToken, HttpServletRequest request) {

        // Refresh Token 존재하지 않을 경우
        if (!StringUtils.hasText(refreshToken) )
            return false;

        // Refresh Token 유효성 검증
        String validateResult = jwtProvider.validateToken(refreshToken);
        if ("EXPIRED_TOKEN".equals(validateResult))     //= 만료된 토큰
            return false;
        else if (!"".equals(validateResult)) {          // 비정상 토큰
            request.setAttribute("exception", validateResult);      // 에러
            return false;
        }

        // 토큰 Payload 검증
        if (!jwtProvider.payLoadValid(refreshToken, "REFRESH"))
            return false;

        // 토큰의 만료 일자를 확인하여 만기 일자가 가깝다면, 재발급
        if (jwtProvider.isReissued(refreshToken))
            return false;

        // Refresh Token 으로 Access Token 새로 갱신
        Authentication auth = jwtProvider.getAuthentication(refreshToken);
        String uuid = String.valueOf(UUID.randomUUID());
        String newAccessToken = jwtProvider.createToken(auth, uuid);
        jwtProvider.changeNewToken(refreshToken, newAccessToken);
        request.setAttribute("AccessTokenData", newAccessToken);

        return true;
    }
}