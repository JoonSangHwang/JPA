package com.junsang.member.security.jwt;

import com.junsang.member.dto.ReqLogin;
import com.junsang.member.entity.TokenEntity;
import com.junsang.member.repository.TokenRepository;
import com.junsang.member.security.exception.ErrorCode;
import com.junsang.member.security.exception.LoginStepException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@RestController
public class JwtController {

    private final Logger logger = LoggerFactory.getLogger(JwtController.class);

    @Autowired
    private JwtProvider jwtProvider;

    @Autowired
    private AuthenticationManagerBuilder authenticationManagerBuilder;

    @Autowired
    private TokenRepository tokenRepository;


    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private PasswordEncoder passwordEncoder;


    @PostMapping("/ipa/jwtLogin")
    public ResponseEntity<JwtTokenDto> authorize(@RequestBody ReqLogin reqLogin, HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

        HttpHeaders httpHeaders = new HttpHeaders();

        String accessToken = (String) request.getAttribute("AccessTokenData");
        String refreshToken = (String) request.getAttribute("RefreshTokenData");

        return new ResponseEntity<>(new JwtTokenDto(accessToken, refreshToken), httpHeaders, HttpStatus.OK);
    }


    @PostMapping("/api/tokenIssuance")
    public ResponseEntity<JwtTokenDto> tokenReissued(@RequestBody ReqLogin reqLogin) {

        // 토큰 생성
        UsernamePasswordAuthenticationToken tokenBeforeAuth = new UsernamePasswordAuthenticationToken(
                reqLogin.getEmail()             // principal   - 이메일
                , reqLogin.getPassword()        // credentials - 패스워드
                , new ArrayList<>()
        );

        // 토큰을 매니저에게 인증 위임 => loadUserByUsername() 실행하러 go
        Authentication auth = authenticationManagerBuilder.getObject().authenticate(tokenBeforeAuth);



        String uuid = String.valueOf(UUID.randomUUID());
        // Access Token 발급
        String accessToken = jwtProvider.createToken(auth, uuid);

        // Refresh Token 발급
        String refreshToken = jwtProvider.createToken(auth, uuid);

        jwtProvider.tokenSaveInCache(accessToken, refreshToken, uuid);

        // 인증 객체 저장
        SecurityContextHolder.getContext().setAuthentication(auth);



        // 클라이언트에게 반환
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add("accessToken", "Bearer " + accessToken);
        httpHeaders.add("refreshToken", "Bearer " + refreshToken);

        return new ResponseEntity<>(new JwtTokenDto(accessToken, refreshToken), httpHeaders, HttpStatus.OK);
    }

    @RequestMapping("/ipa/move")
    public String aaa(HttpServletRequest request) {

        String accessToken = (String) request.getAttribute("AccessTokenData");
        Authentication authentication = jwtProvider.getAuthentication(accessToken);

        SecurityContextHolder.getContext().setAuthentication(authentication);

        return request.getRequestURI();
    }


    @GetMapping("/ipa/test01")
    public ResponseEntity<JwtTokenDto> test01(@RequestBody ReqLogin reqLogin, HttpServletRequest request) {



        return new ResponseEntity<>(HttpStatus.OK);
    }

    @PostMapping("/ipa/test02")
    public ResponseEntity<JwtTokenDto> test02(@RequestBody ReqLogin reqLogin, HttpServletRequest request) {


        return new ResponseEntity<>(HttpStatus.OK);
    }

}
