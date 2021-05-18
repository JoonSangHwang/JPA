package com.junsang.member.security.jwt;

import com.junsang.member.security.jwt.exception.ErrorCode;
import com.junsang.member.security.jwt.exception.ErrorMessage;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * [인증 에러]
 *
 * 유효한 자격 증명을 제공하지 않고 접근 시, AuthenticationEntryPoint 발동
 * - 토큰이 존재하지 않은 경우
 * - 토큰이 만료 된 경우
 * - 토큰 서명이 다른 경우
 *
 * 참고: 리다이렉트를 사용한다면 여기서 원하는 곳으로 리다이렉트하여 Controller Advice처럼 Spring에서 예외 처리가 가능하다.
 */
@Slf4j
@Component
public class JwtAuthEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {

        String exception = (String) request.getAttribute("exception");
        ErrorCode errorCode;

        log.debug("log: exception: {} ", exception);

        // 토큰 없는 경우
        if (exception == null) {
            errorCode = ErrorCode.NON_LOGIN;
            setResponse(response, errorCode);
            return;
        }

        // 토큰 만료된 경우
        if (exception.equals(ErrorCode.EXPIRED_TOKEN.getCode())) {
            errorCode = ErrorCode.EXPIRED_TOKEN;
            setResponse(response, errorCode);
            return;
        }

        // 토큰 서명 다른 경우
        if (exception.equals(ErrorCode.INVALID_TOKEN.getCode())) {
            errorCode = ErrorCode.INVALID_TOKEN;
            setResponse(response, errorCode);
        }

        // 지원되지 않는 JWT 서명 입니다.
        if (exception.equals(ErrorCode.UNSUPRT_TOKEN.getCode())) {
            errorCode = ErrorCode.UNSUPRT_TOKEN;
            setResponse(response, errorCode);
        }

        // JWT 토큰이 잘 못 된 경우
        if (exception.equals(ErrorCode.ILLEGAL_TOKEN.getCode())) {
            errorCode = ErrorCode.ILLEGAL_TOKEN;
            setResponse(response, errorCode);
        }

        // JWT 오류
        if (exception.equals(ErrorCode.EXCPTIN_TOKEN.getCode())) {
            errorCode = ErrorCode.EXCPTIN_TOKEN;
            setResponse(response, errorCode);
        }
    }

    /**
     * 한글 출력을 위해 getWriter() 사용
     */
    private void setResponse(HttpServletResponse response, ErrorCode errorCode) throws IOException {
        response.setContentType("application/json;charset=UTF-8");
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.getWriter().println("{ \"message\" : \"" + errorCode.getMessage()
                + "\", \"code\" : \"" + errorCode.getCode()
                + "\", \"status\" : " + errorCode.getStatus()
                + ", \"errors\" : [ ] }");
    }
}
