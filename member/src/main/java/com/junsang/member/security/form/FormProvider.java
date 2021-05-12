package com.junsang.member.security.form;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

public class FormProvider implements AuthenticationProvider {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private UserDetailsService customUserDetailsService;



    public FormProvider(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    /**
     *
     * @param authentication
     *
     * - principal     : Token 에서 넘어온 값
     * - credentials   : Token 에서 넘어온 값
     * - authorities   :
     * - details       :
     * - authenticated :
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        /**
         * 파마리터 authentication
         */
        String email = (String) authentication.getPrincipal();
        String password = (String) authentication.getCredentials();


        //== [S] 인증 로직
        User user = (User) customUserDetailsService.loadUserByUsername(email);
        System.out.println();

        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new BadCredentialsException("Invalid Password");
        }
        //== [E] 인증 로직



        //== [S] 인증 완료

        // 토큰 생성
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                user.getUsername(),             // 이메일
                null,                 // 패스 워드
                user.getAuthorities());         // 권한정보

        // 토큰 반환
        return usernamePasswordAuthenticationToken;
    }



    /**
     * AuthenticationFilter 에서 Manager 로 부터 전달 된 인증 객체의 타입 검증
     *
     * - expect(UsernamePasswordAuthenticationToken.class)
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
