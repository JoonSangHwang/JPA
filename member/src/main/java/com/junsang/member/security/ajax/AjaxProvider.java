package com.junsang.member.security.ajax;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.transaction.Transactional;

public class AjaxProvider implements AuthenticationProvider {

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    /**
     * 인증 검증
     *
     * @param authentication    AuthenticationManager 가 주는 객체로, 사용자가 입력한 계정 정보가 담겨 있다.
     */
    @Override
    @Transactional
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        // 사용자가 입력한 내용 추출
        String email = (String) authentication.getPrincipal();
        String password = (String) authentication.getCredentials();

        //== [S] 인증 로직
        User user = (User) userDetailsService.loadUserByUsername(email);

        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new BadCredentialsException("Invalid Password");
        }
        //== [E] 인증 로직


        //== [S] 인증 완료

        // 토큰 생성
        AjaxToken customAjaxToken = new AjaxToken(
                user.getUsername(),             // 이메일
                null,                 // 패스 워드
                user.getAuthorities());         // 권한정보

        // 토큰 반환
        return customAjaxToken;
    }

    /**
     * 인증 객체가 토큰 타입과 같을 경우, Provider 동작
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(AjaxToken.class);
    }
}