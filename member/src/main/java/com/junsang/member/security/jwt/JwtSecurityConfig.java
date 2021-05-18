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

        http.cors().disable();
        http.csrf().disable();
        http.httpBasic().disable();
        
        http
                // Exception Handling
                .exceptionHandling()
                .authenticationEntryPoint(jwtAuthEntryPoint)
                .accessDeniedHandler(jwtAccessDeniedHandler)

                // Session Remove
        .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        ;

        http
                .authorizeRequests()
                .antMatchers("/ipa/hello").permitAll()
                .antMatchers("/ipa/jwtLogin").permitAll()
                .anyRequest().authenticated()
        .and()
                .addFilterBefore(new JwtFilter(jwtProvider), UsernamePasswordAuthenticationFilter.class)

        ;
    }


}
