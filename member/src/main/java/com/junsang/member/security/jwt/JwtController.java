package com.junsang.member.security.jwt;

import com.junsang.member.dto.ReqLogin;
import com.junsang.member.dto.TokenDto;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
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

    @PostMapping("/ipa/jwtLogin")
    public ResponseEntity<TokenDto> authorize(@RequestBody ReqLogin reqLogin) {

        //======[인증 전]======

        // 토큰 생성
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                reqLogin.getEmail()             // principal   - 이메일
                , reqLogin.getPassword()      // credentials - 패스워드
                , new ArrayList<>()
        );


        // 토큰을 매니저에게 인증 위임 => loadUserByUsername() 실행하러 go
        User user = (User) authenticationManagerBuilder.getObject().authenticate(usernamePasswordAuthenticationToken);
        Authentication auth = authenticationManagerBuilder.getObject().authenticate(usernamePasswordAuthenticationToken);
        user.getUsername();
        user.getPassword();

        //======[인증 후]======

        // 인증 객체 저장
        SecurityContextHolder.getContext().setAuthentication(auth);

        // JWT 토큰 생성
        String newJwtToken = jwtProvider.createToken(auth);

        // 클라이언트에게 반환
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add("AuthHeader", "Bearer " + newJwtToken);
//        httpHeaders.add("email", email);
//        httpHeaders.add(HttpStatus.OK.value());                  // 응답값 200
//        httpHeaders.setContentType(MediaType.APPLICATION_JSON_VALUE);  // 미디어타입 JSON

        return new ResponseEntity<>(new TokenDto(newJwtToken), httpHeaders, HttpStatus.OK);
    }
}
