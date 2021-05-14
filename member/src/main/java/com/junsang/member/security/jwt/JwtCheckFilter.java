package com.junsang.member.security.jwt;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtCheckFilter extends OncePerRequestFilter {

    private final Logger logger = LoggerFactory.getLogger(JwtCheckFilter.class);

    private JwtProvider jwtProvider;

//    @Value("${token.header}")
    private String AUTHORITIES_HEADER = "AuthHeader";


    private JwtCheckFilter jwtCheckFilter;

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
