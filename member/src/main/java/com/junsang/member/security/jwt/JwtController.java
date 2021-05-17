package com.junsang.member.security.jwt;

import com.junsang.member.dto.ReqLogin;
import com.junsang.member.dto.TokenDto;
import com.junsang.member.security.ajax.AjaxToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;

@RestController
public class JwtController {

    @Autowired
    private JwtProvider jwtProvider;

    @Autowired
    private AuthenticationManagerBuilder authenticationManagerBuilder;


    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @PostMapping("/ipa/jwtLogin")
    public ResponseEntity<TokenDto> authorize(@RequestBody ReqLogin reqLogin) {


        Object objBeforeAuth = SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        // JWT 토큰을 가지고 있는 상태
        if (objBeforeAuth instanceof UserDetails) {

            // 기존 토큰 인증 삭제
            SecurityContextHolder.clearContext();

            // 리프레시 토큰의 유효기간을 체크


        }


        // JWT 토큰을 가지고 있지 않음
        else {

            // Access Token 발급
            String AccessToken = jwtProvider.createToken(auth);

            // Refresh Token 발급
            String refreshToken = jwtProvider.createToken(auth);
        }











        //=====[인증 전]======
        
        
        

        // 토큰 생성
        UsernamePasswordAuthenticationToken tokenBeforeAuth = new UsernamePasswordAuthenticationToken(
                        reqLogin.getEmail()             // principal   - 이메일
                        , reqLogin.getPassword()        // credentials - 패스워드
                        , new ArrayList<>()
        );


        // 토큰을 매니저에게 인증 위임 => loadUserByUsername() 실행하러 go
        Authentication auth = authenticationManagerBuilder
                .getObject()
                .authenticate(tokenBeforeAuth);



        //======[인증 후]======

        // 인증 객체 저장
        SecurityContextHolder.getContext().setAuthentication(auth);


        // 클라이언트에게 반환
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add("AuthHeader", "Bearer " + newJwtToken);

        return new ResponseEntity<>(new TokenDto(newJwtToken), httpHeaders, HttpStatus.OK);
    }
}
