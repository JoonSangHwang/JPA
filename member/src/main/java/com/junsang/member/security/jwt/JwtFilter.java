package com.junsang.member.security.jwt;
import com.junsang.member.entity.TokenEntity;
import com.junsang.member.repository.TokenRepository;
import com.junsang.member.security.jwt.exception.ErrorCode;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.Cacheable;
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

    private String AUTHORITIES_ACCESS_TOKEN_HEADER  = "AuthHeader";
    private String AUTHORITIES_REFRESH_TOKEN_HEADER = "refreshTokenHeader";

    @Autowired private TokenRepository tokenRepository;
    @Autowired private JwtException jwtException;

    private JwtProvider jwtProvider;

    public JwtFilter(JwtProvider jwtProvider) {
        this.jwtProvider = jwtProvider;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        /**
         * 요청 헤더에서 Token 정보 추출
         **/
        Map<String, String>   tokenInfo = resolveToken(request);
        String accessToken  = tokenInfo.get("accessToken");
        String refreshToken = tokenInfo.get("refreshToken");


        /**
         * Access Token & Refresh Token 유효성 검사
         **/
//        boolean isReissued = tokenValid(accessToken, refreshToken, request);
        boolean isReissued = accessTokenValidate(accessToken, refreshToken, request);




        /**
         * 재발급 여부에 따라 Controller 이동
         **/
        String str = (String) request.getAttribute("exception");
        if (!"".equals(str))
            filterChain.doFilter(request, response);
        else
            resolveRequest(isReissued, request, response, filterChain, accessToken, refreshToken);
    }


    /**
     * true 비정상
     * false 정상
     */
    private boolean accessTokenValidate(String accessToken, String refreshToken, HttpServletRequest request) {

        // Access Token 존재 여부 검증
        if (!StringUtils.hasText(accessToken))
            return refreshTokenValidate(refreshToken, request);

        // Access Token 유효성 검증
        String validateResult = jwtProvider.validateToken(accessToken);
        if ("EXPIRED_TOKEN".equals(validateResult))     //= 만료된 토큰
            return refreshTokenValidate(refreshToken, request);
        else if ("NON_LOGIN".equals(validateResult))    //= 토큰 없음
            return true;
        else if (!"".equals(validateResult)) {          //= 비정상 토큰
            request.setAttribute("exception", validateResult);      // 에러
            return true;
        }

        // 토큰 Payload 검증
        if (payLoadValid(accessToken))
            return true;

        // 토큰 만료 시간에 따른 재발급 여부
        return jwtProvider.whetherTheTokenIsReissued(accessToken);
    }



    @Cacheable(key = "#cnt", value = "member")
    private boolean payLoadValid(String token) {

        // 토큰에서 UUID 가져오기
//        String tokenUUID = jwtProvider.getTokenUUID(token);
//
//        // Redis 조회
//        TokenEntity tokenInfo = tokenRepository.findById(1L).orElse(null);
//        if (tokenInfo == null)
//            return true;
//
//        if ("N".equals(tokenInfo.getUsableYn()))
//            return true;

        return false;
    }




    private boolean refreshTokenValidate(String refreshToken, HttpServletRequest request) {

        // Refresh Token 존재하지 않을 경우
        if (!StringUtils.hasText(refreshToken) )
            return true;

        // Refresh Token 유효성 검증
        String validateResult = jwtProvider.validateToken(refreshToken);
        if ("EXPIRED_TOKEN".equals(validateResult))     // 만료된 토큰
            return true;
        else if (!"".equals(validateResult)) {           // 비정상 토큰
            request.setAttribute("exception", validateResult);      // 에러
        }

        // 토큰 Payload 검증
        if (payLoadValid(refreshToken))
            return true;

        return jwtProvider.whetherTheTokenIsReissued(refreshToken);
    }



















//
//
//    /**
//     * 토큰 유효성 검사
//     */
//    private boolean tokenValid(String accessToken, String refreshToken, HttpServletRequest request) {
//
//        // Access Token [O]  ||  Refresh Token [O],[X]
//        if (StringUtils.hasText(accessToken) ) {
//            return accessTokenLogic(accessToken, refreshToken, request);
//        }
//
//        // Access Token [X]  ||  Refresh Token [O]
//        else if (StringUtils.hasText(refreshToken) ) {
//            return refreshTokenLogic(refreshToken, request);
//        }
//
//        // Access Token [X]  ||  Refresh Token [X]
//        else {
//            log.info("===== [JS Log] 사용자 '{}' 님의 Access Token 과 Refresh Token 둘 다 존재하지 않습니다. : '{}' ", request.getAttribute("email"), refreshToken);
//            log.info("===== [JS Log] 사용자 '{}' 님, 신규 토큰 생성 요청 입니다.", request.getAttribute("email"));
//
//            return true;
//        }
//    }
//
//
//

//
//
//    private boolean accessTokenLogic(String accessToken, String refreshToken, HttpServletRequest request) {
//        log.info("===== [JS Log] 사용자 '{}' 님의 Access Token 이 발견되었습니다 : '{}' ", request.getAttribute("email"), accessToken);
//
//        // Access Token 유효성 검증
//        String exceptionNm = jwtProvider.validateToken(accessToken);
//
//        // 정상 Access Token
//        if ("".equals(exceptionNm)) {
//            log.info("===== [JS Log] 사용자 '{}' 님이 토큰 유효성 검증을 통과하였습니다.", request.getAttribute("email"));
//
//
//            // Access Token Payload 검증
//
//
//            // [재발급] 실제로 Access Token 이 만료되지는 않았지만, 만료 시간에 시간이 가까울 경우
//            if (jwtProvider.whetherTheTokenIsReissued(accessToken)) {
//                log.info("===== [JS Log] 사용자 '{}' 님의 Access Token 은 재발급 대상 입니다.", request.getAttribute("email"));
//                return true;
//            } else {
//
//                // 토큰에서 유저 정보를 가져와 Auth 객체를 만듬
//                Authentication auth2 = jwtProvider.getAuthentication(accessToken);
//
//                // 요청으로 들어온 토큰 그대로 담아 반환
//                request.setAttribute("AccessTokenData", accessToken);
//                request.setAttribute("RefreshTokenData", refreshToken);
//
//                // 시큐리티 컨텍스트에 Auth 객체 저장
//                SecurityContextHolder.getContext().setAuthentication(auth2);
//                log.info("===== [JS Log] Security Context 에 '{} 인증 정보를 저장했습니다. URI: {} '", auth2.getName(), request.getRequestURI());
//            }
//        }
//
//        // 만료 Access Token
//        else if("EXPIRED_TOKEN".equals(exceptionNm)) {
//            log.info("===== [JS Log] 사용자 '{}' 님의 Access Token 은 만료된 토큰 입니다.", request.getAttribute("email"));
//
////            refreshTokenValid();
//
//            // Refresh Token 존재함
//            if (StringUtils.hasText(refreshToken) ) {
//
//
//                String exception2 = jwtProvider.validateToken(refreshToken);
//                if ("".equals(exception2)) {
//
//                }
//
//
//                // [재발급]
//                else if("EXPIRED_TOKEN".equals(exception2)) {
//                    return true;
//                }
//
//                // Refresh Token 유효성 검증 실패
//                else {
//
//                }
//
//            }
//
//            // Refresh Token 존재하지 않음
//            else {
//                log.info("===== [JS Log] 사용자 '{}' 님의 Refresh Token 을 찾지 못했습니다.", request.getAttribute("email"));
//                return true;
//            }
//            // ?
//        }
//
//        // 비정상 Access Token
//        else {
//            log.info("===== [JS Log] 사용자 '{}' 님이 토큰 유효성 검증에 실패하였습니다.", request.getAttribute("email"));
//            request.setAttribute("exception", exceptionNm);
//        }
//
//        return false;
//    }
//
//
//    private void refreshTokenValid(String refreshToken, HttpServletRequest request) {
//        log.info("===== [JS Log] 사용자 '{}' 님의 Access Token 이 존재하지 않습니다.", request.getAttribute("email"));
//
//
//
//
//    }
//
//    private boolean refreshTokenLogic(String refreshToken, HttpServletRequest request) {
//        log.info("===== [JS Log] 사용자 '{}' 님의 Access Token 은 발견하지 못하였으며, Refresh Token 은 발견되었습니다. : '{}' ", request.getAttribute("email"), refreshToken);
//
//        // Refresh Token 유효성 검사
//        String exceptionNm = jwtProvider.validateToken(refreshToken);
//        if ("".equals(exceptionNm)) {
//            log.info("===== [JS Log] 사용자 '{}' 님이 토큰 유효성 검증을 통과하였습니다.", request.getAttribute("email"));
//
//            // Refresh Token Payload 검증
//
//
//            // Refresh Token 을 이용해 Access Token 구하기
//            String accessToken = "1";
//
//            // 토큰 담아서 넘겨주기
//            request.setAttribute("AccessTokenData", accessToken);
//            request.setAttribute("RefreshTokenData", refreshToken);
//
//            // 토큰에서 유저 정보를 가져와 Auth 객체를 만듬
//            Authentication auth2 = jwtProvider.getAuthentication(accessToken);
//
//            // 시큐리티 컨텍스트에 Auth 객체 저장
//            SecurityContextHolder.getContext().setAuthentication(auth2);
//            log.debug("Security Context 에 '{} 인증 정보를 저장했습니다. URI: {} '", auth2.getName(), request.getRequestURI());
//        }
//
//        // Refresh Token 유효성 검증 실패
//        else {
//            log.info("===== [JS Log] 사용자 '{}' 님이 토큰 유효성 검증에 실패하였습니다.", request.getAttribute("email"));
//            request.setAttribute("exception", ErrorCode.INVALID_TOKEN.getCode());
//        }
//
//        return false;
//    }


    /**
     * 요청 헤더에서 Token 정보 추출
     */
    public Map<String, String> resolveToken(HttpServletRequest request) {
        Map<String, String> tokenInfo = new HashMap();

        // 액세스 토큰 추출
        String bearerAccessToken = request.getHeader(AUTHORITIES_ACCESS_TOKEN_HEADER);
        if (StringUtils.hasText(bearerAccessToken) && bearerAccessToken.startsWith("Bearer "))
            tokenInfo.put("accessToken", bearerAccessToken.substring(7));
        else tokenInfo.put("accessToken", null);


        // 리프레시 토큰 추출
        String bearerRefreshToken = request.getHeader(AUTHORITIES_REFRESH_TOKEN_HEADER);
        if (StringUtils.hasText(bearerRefreshToken) && bearerRefreshToken.startsWith("Bearer "))
            tokenInfo.put("refreshToken", bearerRefreshToken.substring(7));
        else tokenInfo.put("refreshToken", null);

        return tokenInfo;
    }

    private void resolveRequest(boolean isReissued, HttpServletRequest request, HttpServletResponse response, FilterChain filterChain, String accessToken, String refreshToken) throws ServletException, IOException {

        if (isReissued) {
            log.info("===== [JS Log] 사용자 '{}' 님, 신규 토큰 및 재발급 요청 입니다.", request.getAttribute("email"));
            request.getRequestDispatcher("/api/jwtLogin").forward(request, response);
        }


        // 토큰에서 유저 정보를 가져와 Auth 객체를 만듬
        Authentication auth2 = jwtProvider.getAuthentication(accessToken);

        // 요청으로 들어온 토큰 그대로 담아 반환
        request.setAttribute("AccessTokenData", accessToken);
        request.setAttribute("RefreshTokenData", refreshToken);

        // 시큐리티 컨텍스트에 Auth 객체 저장
        SecurityContextHolder.getContext().setAuthentication(auth2);
        log.info("===== [JS Log] Security Context 에 '{} 인증 정보를 저장했습니다. URI: {} '", auth2.getName(), request.getRequestURI());


        log.info("===== [JS Log] 사용자 '{}' 님, 인증 완료 입니다.", request.getAttribute("email"));
        filterChain.doFilter(request, response);
    }
}