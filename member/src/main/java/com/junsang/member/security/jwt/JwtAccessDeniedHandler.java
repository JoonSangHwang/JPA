package com.junsang.member.security.jwt;

import com.junsang.member.security.exception.ErrorCode;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * [권한 에러]
 *
 * 필요한 권한이 존재하지 않는 경우, AccessDeniedHandler 발동
 */
@Component
public class JwtAccessDeniedHandler implements AccessDeniedHandler {

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        response.sendError(HttpServletResponse.SC_FORBIDDEN);   // 403 에러

        response.setContentType("application/json;charset=UTF-8");
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.getWriter().println("{ \"message\" : \"" + ErrorCode.ACCESS_DENIED.getMessage()
                + "\", \"code\" : \"" +  ErrorCode.ACCESS_DENIED.getCode()
                + "\", \"status\" : " + ErrorCode.ACCESS_DENIED.getStatus()
                + ", \"errors\" : [ ] }");
    }
}
