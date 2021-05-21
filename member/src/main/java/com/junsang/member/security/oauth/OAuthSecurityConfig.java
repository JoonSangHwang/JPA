package com.junsang.member.security.oauth;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.web.filter.CharacterEncodingFilter;

//@Configuration
//@EnableWebSecurity
//@Slf4j
//@Order(40)
//public class OAuthSecurityConfig extends WebSecurityConfigurerAdapter {
//
//
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        CharacterEncodingFilter filter = new CharacterEncodingFilter();
//
//        http.cors().disable();
//        http.csrf().disable();
//
//        http
//                .authorizeRequests()
//                .antMatchers("/", "/oauth2/**", "/login/**", "/css/**", "/images/**", "/js/**", "/console/**").permitAll()
//                .antMatchers("/facebook").hasAuthority(FACEBOOK.getRoleType())
//                .antMatchers("/google").hasAuthority(GOOGLE.getRoleType())
//                .antMatchers("/kakao").hasAuthority(KAKAO.getRoleType())
//        .and()
//                .oauth2Login()
//                .defaultSuccessUrl("/loginSuccess")         // 로그인 성공 시, 이동 할 URL
//                .failureUrl("/loginFailure")                // 로그인 실패 시, 이동 할 URL
//                .userInfoEndpoint()                         // 로그인 성공 후, 로그인 기능에 대한 여러 설정의 진입점
//                .userService(customOAuth2UserService)       // 로그인 성공 후, 후속 조치 UserService 인터페이스 구현체 [리소스 서버에서 받아온 사용자 정보를 핸들링]
//                .and()
//                .exceptionHandling()
//                .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
//                .and()
//
//                // 로그아웃
//                .logout()
//                .logoutUrl("/logout")
//                .logoutSuccessUrl("/")          // 로그아웃 성공 시, 이동 할 URL
//                .deleteCookies("JSESSIONID")    // 쿠키 삭제
//                .invalidateHttpSession(true)
//                .and()
//                .addFilterBefore(filter, CsrfFilter.class)
//        ;
//
//    }
//}
