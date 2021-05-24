package com.junsang.member.security.jwt;

import com.junsang.member.security.jwt.JwtFilter;
import com.junsang.member.security.jwt.JwtProvider;
import com.junsang.member.security.oauth.CustomOAuth2UserService;
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
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static com.junsang.member.entity.enumType.RoleType.*;

@Configuration
@EnableWebSecurity      // 시큐리티 활성화
@Order(40)
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



        // H2 데이터베이스는 HTML 프레임으로 데이터가 나누어져 있어, console 화면을 사용하기 위해 disable 처리
        http
                .headers().frameOptions().disable();



        http
                .authorizeRequests()
                .antMatchers("/", "/oauth2/**", "/login/**", "/css/**", "/images/**", "/js/**", "/console/**").permitAll();


        /** Form **/
        http
                .authorizeRequests()                                      // 요청에 의한 보안검사 시작
                .antMatchers("/").permitAll()                   // [페이지] index
                .antMatchers("/mainPage").permitAll()           // [페이지] 메인
                .antMatchers("/loginPage").permitAll()          // [페이지] 로그인
                .antMatchers("/signUpPage").permitAll()         // [페이지] 회원가입

                .antMatchers("/signUp").permitAll()

                .antMatchers("/loginRequest").permitAll();

        /** JWT **/
        http
                // Exception Handling
                .exceptionHandling()
                .authenticationEntryPoint(jwtAuthEntryPoint)
                .accessDeniedHandler(jwtAccessDeniedHandler)

                // Session Remove
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                // Authenticate Config
                .and()
                .authorizeRequests()
                .antMatchers("/ipa/hello").permitAll()
                .antMatchers("/ipa/jwtLogin").permitAll()
                .anyRequest().authenticated()
                .and()
                .addFilterBefore(new JwtFilter(jwtProvider), UsernamePasswordAuthenticationFilter.class)
        ;
    }
}
