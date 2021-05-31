package com.junsang.member.security.jwt;

import com.junsang.member.dto.ReqLogin;
import com.junsang.member.entity.TokenEntity;
import com.junsang.member.repository.TokenRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
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
    public ResponseEntity<JwtTokenDto> authorize(@RequestBody ReqLogin reqLogin, HttpServletRequest request) {

        HttpHeaders httpHeaders = new HttpHeaders();

        String accessToken = (String) request.getAttribute("AccessTokenData");
        String refreshToken = (String) request.getAttribute("RefreshTokenData");

        return new ResponseEntity<>(new JwtTokenDto(accessToken, refreshToken), httpHeaders, HttpStatus.OK);
    }


    @PostMapping("/api/jwtLogin")
    public ResponseEntity<JwtTokenDto> reissued(@RequestBody ReqLogin reqLogin) {

//        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        HttpHeaders httpHeaders = new HttpHeaders();

//        String username = principal.toString();
        logger.info("[JS LOG] Security Context 에 인증 정보가 없습니다. {}", reqLogin.getEmail());

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

        // Access Token 발급
        String accessToken = jwtProvider.createToken(auth);

        // Refresh Token 발급
        String refreshToken = jwtProvider.createToken(auth);

        // 인증 객체 저장
        SecurityContextHolder.getContext().setAuthentication(auth);

        tokenCacheSave(accessToken, refreshToken);

        // 클라이언트에게 반환
        httpHeaders.add("accessToken", "Bearer " + accessToken);
        httpHeaders.add("refreshToken", "Bearer " + refreshToken);

        return new ResponseEntity<>(new JwtTokenDto(accessToken, refreshToken), httpHeaders, HttpStatus.OK);
    }

    @Cacheable(key = "#uuid", value = "memberAuth")
    private void tokenCacheSave(String accessToken, String refreshToken) {

        String uuid = String.valueOf(UUID.randomUUID());

        TokenEntity tokenEntity = TokenEntity.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .uuid(uuid)
                .usableYn("Y")
                .build();

         tokenRepository.save(tokenEntity);
    }
}
