package com.junsang.member.security.form;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.junsang.member.dto.ReqLogin;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;

public class FromFilter extends UsernamePasswordAuthenticationFilter {

    private ObjectMapper objectMapper = new ObjectMapper();

    public FromFilter() {
//        super("/api/login");     // 요청 정보가 URL 과 매칭 되면 필터 발동 (1/2)
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        try {
            // 사용자의 입력값
            ReqLogin requestLogin = new ObjectMapper().readValue(request.getInputStream(), ReqLogin.class);

            // [인증 전] 토큰 생성
            UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                            requestLogin.getEmail()             // principal   - 이메일
                            , requestLogin.getPassword()        // credentials - 패스워드
                            , new ArrayList<>());

            // [인증 전] 토큰을 매니저에게 인증 위임
            Authentication auth = getAuthenticationManager().authenticate(usernamePasswordAuthenticationToken);

            // 인증이 정상적으로 호출 될 경우, auth 반환
            return auth;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {

//        UserDto userDetails = userService.getUserDetailsByEmail(userName);
//
//        String token = Jwts.builder()
//                .setSubject(userDetails.getUserId())
//                .setExpiration(new Date(System.currentTimeMillis() + Long.parseLong(tokenExpirationTime)))
//                .signWith(SignatureAlgorithm.HS512, tokenSecret)
//                .compact();
//
//        response.addHeader("token", token);
//        response.addHeader("userId", userDetails.getUserId());
//
        super.successfulAuthentication(request, response, chain, authResult);
    }
}
