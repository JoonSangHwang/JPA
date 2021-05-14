package com.junsang.member.security.jwt;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity      // 시큐리티 활성화
@Order(30)
@EnableGlobalMethodSecurity(prePostEnabled = true)  // @PreAuthorize 어노테이션을 메소드 단위로 사용하기 위해 추가
public class JwtSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private AccessDeniedHandler jwtAccessDeniedHandler;

    @Autowired
    private AuthenticationEntryPoint jwtAuthEntryPoint;

    @Autowired
    private AuthenticationSuccessHandler jwtSuccessHandler;



    private JwtProvider jwtProvider;

    public JwtSecurityConfig(JwtProvider jwtProvider) {
        this.jwtProvider = jwtProvider;
    }



    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http
                .cors().disable();
        http
                .csrf().disable();
        
        http
//                .exceptionHandling()
//                .authenticationEntryPoint(jwtAuthEntryPoint)
//                .accessDeniedHandler(jwtAccessDeniedHandler)

                // 세션을 사용하지 않기 떄문에, 세션 삭제
//        .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                
//        .and()
//                // HttpServletRequest 를 사용하는 요청들에 대한 접근 제한 설정
//                .authorizeRequests()
//                .antMatchers("/api/hello").permitAll()
//                .antMatchers("/api/authenticate").permitAll()
//                .antMatchers("/api/signup").permitAll()
//                .anyRequest().authenticated()
//        .and()
//                .addFilterBefore(getJwtFilter(), UsernamePasswordAuthenticationFilter.class)
        ;

        http
//                .antMatcher("/ipa/jwtLogin")
                .authorizeRequests()
                .antMatchers("/ipa/hello").permitAll()
                .anyRequest().authenticated()
        .and()
                .addFilterBefore(new JwtCheckFilter(jwtProvider), UsernamePasswordAuthenticationFilter.class)
        ;
    }
}
