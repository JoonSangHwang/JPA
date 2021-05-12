package com.junsang.member.security.form;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity      // 시큐리티 활성화
public class FormSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private AuthenticationProvider formProvider;                      // 인증 Provider

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http
                .cors().disable();
        http
                .csrf().disable();

        http
                .authorizeRequests()
                .antMatchers("/", "/oauth2/**", "/login/**", "/css/**", "/images/**", "/js/**", "/console/**").permitAll();

        http
                .authorizeRequests()                                      // 요청에 의한 보안검사 시작
                .antMatchers("/").permitAll()                   // [페이지] index
                .antMatchers("/mainPage").permitAll()           // [페이지] 메인
                .antMatchers("/loginPage").permitAll()          // [페이지] 로그인
                .antMatchers("/signUpPage").permitAll()         // [페이지] 회원가입

                .antMatchers("/signUp").permitAll()

                .antMatchers("/loginRequest").permitAll()
                .and()

                .addFilter(getAuthenticationFilter())


        ;

        // H2 데이터베이스는 HTML 프레임으로 데이터가 나누어져 있다 -> 무시
        http
                .headers().frameOptions().disable();


    }

    /**
     * 인증 필터 적용
     */
    private FromFilter getAuthenticationFilter() throws Exception {
        FromFilter fromFilter = new FromFilter();
        fromFilter.setAuthenticationManager(authenticationManager());
        return fromFilter;
    }

    /**
     * 메서드 설명
     * - AuthenticationProvider 는 AuthenticationManagerBuilder 를 통해 설정 가능
     * - 인증 객체를 만들 수 있도록 제공
     *
     * 참고 설명
     * - Security 인증 시, AuthenticationManager 가 인증을 AuthenticationProvider 에게 위임
     * - AuthenticationProvider 는 인증 시, CustomFormProvider 를 참조하도록 설정 함
     * - CustomFormProvider 는 DB 에서 사용자를 조회하여 인증을 진행하려는 목적
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(formProvider);
    }

}
