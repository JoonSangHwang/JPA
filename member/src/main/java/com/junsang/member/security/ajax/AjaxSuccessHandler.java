package com.junsang.member.security.ajax;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.junsang.member.dto.ReqLogin;
import com.junsang.member.dto.ResLogin;
import com.junsang.member.entity.Members;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;

public class AjaxSuccessHandler implements AuthenticationSuccessHandler {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Value("${token.expiration_time}")
    private String jwtTokenExpirationTime;

    @Value("${token.secret}")
    private String jwtTokenSecret;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        String email = (String) authentication.getPrincipal();

        // JWT 토큰 생성
        String token = Jwts.builder()
                .setSubject(email)
                .setExpiration(new Date(System.currentTimeMillis() + Long.parseLong(jwtTokenExpirationTime)))
                .signWith(SignatureAlgorithm.HS512, jwtTokenSecret)
                .compact();

        response.addHeader("jwtToken", token);
        response.addHeader("email", email);
        response.setStatus(HttpStatus.OK.value());                  // 응답값 200
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);  // 미디어타입 JSON

//        HttpSession session = request.getSession();
//        session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, SecurityContextHolder.getContext());

        // JSON 형식으로 클라이언트에게 반환 됨
        objectMapper.writeValue(response.getWriter(), email);
    }
}
