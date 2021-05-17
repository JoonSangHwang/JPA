package com.junsang.member.security.jwt;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

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
public class JwtCheckFilter extends OncePerRequestFilter {

    private final Logger logger = LoggerFactory.getLogger(JwtCheckFilter.class);

    private String AUTHORITIES_HEADER = "AuthHeader";
    private JwtProvider jwtProvider;

    public JwtCheckFilter(JwtProvider jwtProvider) {
        this.jwtProvider = jwtProvider;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;

        // 헤더에서 토큰 추출
        String jwt = resolveToken(httpServletRequest);

        // 현재 URI
        String requestURI = httpServletRequest.getRequestURI();

        // 토큰 유효성 검사
        if (StringUtils.hasText(jwt) && jwtProvider.validateToken(jwt)) {
            // 토큰에서 유저 정보를 가져와 Auth 객체를 만듬
            Authentication auth2 = jwtProvider.getAuthentication(jwt);

            // 시큐리티 컨텍스트에 Auth 객체 저장
            SecurityContextHolder.getContext().setAuthentication(auth2);
            logger.debug("Security Context 에 '{} 인증 정보를 저장했습니다. URI: {} '", auth2.getName(), requestURI);
        } else {
            logger.debug("유효한 JWT 토큰이 없습니다. URI: {} '", requestURI);
        }

        filterChain.doFilter(request, response);
    }


    /**
     * 헤더에서 토큰 정보를 추출하여 가공 후 반환
     */
    public String resolveToken(HttpServletRequest request) {
        // 헤더에서 토큰 정보를 추출
        String bearerToken = request.getHeader(AUTHORITIES_HEADER);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }








}
