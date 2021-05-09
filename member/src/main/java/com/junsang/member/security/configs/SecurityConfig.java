package com.junsang.member.security.configs;

import com.junsang.member.security.filter.AuthenticationFilter;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity      // 시큐리티 활성화
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/").permitAll()                   // [페이지] index
                .antMatchers("/mainPage").permitAll()           // [페이지] 메인
                .antMatchers("/loginPage").permitAll()          // [페이지] 로그인
                .anyRequest().authenticated()

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
    private AuthenticationFilter getAuthenticationFilter() throws Exception {
        AuthenticationFilter authenticationFilter = new AuthenticationFilter();
        authenticationFilter.setAuthenticationManager(authenticationManager());
        return authenticationFilter;
    }

}
