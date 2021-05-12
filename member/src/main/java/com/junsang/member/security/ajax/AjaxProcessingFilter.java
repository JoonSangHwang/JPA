package com.junsang.member.security.ajax;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.junsang.member.dto.ReqLogin;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.thymeleaf.util.StringUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AjaxProcessingFilter extends AbstractAuthenticationProcessingFilter {

    private ObjectMapper objectMapper = new ObjectMapper();

    public AjaxProcessingFilter() {
        super(new AntPathRequestMatcher("/api/login"));     // 요청 정보가 URL 과 매칭 되면 필터 발동 (1/2)
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {

        //= 인증 조건
        if (!isAjax(request)) {
            throw new IllegalStateException("Authentication is not supported");
        }

        // Email 또는 PASSWORD 가 null 값이라면, 예외
        ReqLogin reqLogin = objectMapper.readValue(request.getReader(), ReqLogin.class);
        if (StringUtils.isEmpty(reqLogin.getEmail()) || StringUtils.isEmpty(reqLogin.getPassword())) {
            throw new IllegalArgumentException("Email or Password is empty");
        }

        // [인증 전] 토큰을 매니저에게 인증 위임
        AjaxToken ajaxAuthToken = new AjaxToken(reqLogin.getEmail(), reqLogin.getPassword());
        Authentication auth = getAuthenticationManager().authenticate(ajaxAuthToken);

        // 인증이 정상적으로 호출 될 경우, auth 반환
        return auth;
    }

    // 요청 정보가 Ajax 라면 필터 발동 (2/2)
    private boolean isAjax(HttpServletRequest httpServletRequest) {
        return "XMLHttpRequest".equals(httpServletRequest.getHeader("X-Requested-with"));
    }
}
