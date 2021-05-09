package com.junsang.member.security.filter;

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
import java.util.Date;

public class AuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        try {
            // 사용자의 입력값
            ReqLogin requestLogin = new ObjectMapper().readValue(request.getInputStream(), ReqLogin.class);

            // 토큰 생성
            UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken
                    = new UsernamePasswordAuthenticationToken(requestLogin.getEmail(), requestLogin.getPassword(), new ArrayList<>());

            // 토큰을 매니저에게 인증 위임
            return getAuthenticationManager().authenticate(usernamePasswordAuthenticationToken);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {


//        String userName = ((org.springframework.security.core.userdetails.User)authResult.getPrincipal()).getUsername();
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
//        super.successfulAuthentication(request, response, chain, authResult);
    }
}
