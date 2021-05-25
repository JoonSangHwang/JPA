package com.junsang.member.security.oauth;

import com.junsang.member.security.jwt.JwtFilter;
import com.junsang.member.security.jwt.JwtProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.web.filter.CharacterEncodingFilter;

import static com.junsang.member.entity.enumType.RoleType.*;

@Configuration
@EnableWebSecurity      // 시큐리티 활성화
@Order(10)
public class OAuth2SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private AccessDeniedHandler jwtAccessDeniedHandler;

    @Autowired
    private AuthenticationEntryPoint jwtAuthEntryPoint;

    @Autowired
    private CustomOAuth2UserService customOAuth2UserService;

    private JwtProvider jwtProvider;

    public OAuth2SecurityConfig(JwtProvider jwtProvider) {
        this.jwtProvider = jwtProvider;
    }

//    @Override
//    public void configure(WebSecurity web) throws Exception {
//        web
//                .ignoring()
//                .antMatchers("/css/**", "/js/**", "/img/**")
//                .antMatchers("/h2-console/**", "/swagger-ui/**")
//                .antMatchers("/")
//                .antMatchers("/mainPage")
//                .antMatchers("/loginPage")
//                .antMatchers("/signUpPage")
//                .antMatchers("/signUp")
//                .antMatchers("/loginRequest")
//                .antMatchers("/ipa/hello")
//                .antMatchers("/ipa/jwtLogin")
//                .antMatchers("/")
//                .antMatchers("/oauth2/**")
//                .antMatchers("/login/**")
//                .antMatchers("/images/**")
//                .antMatchers("/console/**")
//        ;
//    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.cors().disable();
        http.csrf().disable();
//        http.httpBasic().disable();



        // H2 데이터베이스는 HTML 프레임으로 데이터가 나누어져 있어, console 화면을 사용하기 위해 disable 처리
        http
                .headers().frameOptions().disable();

        http
                .authorizeRequests()
                .antMatchers("/").permitAll()                   // [페이지] index
                .antMatchers("/mainPage").permitAll()           // [페이지] 메인
                .antMatchers("/loginPage").permitAll()          // [페이지] 로그인
                .antMatchers("/signUpPage").permitAll()         // [페이지] 회원가입
                .antMatchers("/signUp").permitAll()             // [페이지] 회원가입

                .antMatchers("/loginPage*").permitAll()         // [컨트롤러]

                // JWT
                .antMatchers("/ipa/hello").permitAll()
                .antMatchers("/ipa/jwtLogin").permitAll()

                .antMatchers("/mypage").hasRole("BRONZE")
                .antMatchers("/messages").hasRole("MANAGER")
                .antMatchers("/config").hasRole("ADMIN")
                .antMatchers(
                        "/",
                        "/oauth2/**",
                        "/login/**",
                        "/css/**",
                        "/images/**",
                        "/js/**",
                        "/console/**").permitAll()
                .antMatchers("/facebook").hasAuthority(FACEBOOK.getRoleType())
                .antMatchers("/google").hasAuthority(GOOGLE.getRoleType())
                .antMatchers("/kakao").hasAuthority(KAKAO.getRoleType())
                .anyRequest().authenticated()

//                .and()
//                .antMatcher("/ipa/**").authorizeRequests()
//                .anyRequest().authenticated()
//                .and()
//                .addFilterBefore(new JwtFilter(jwtProvider), UsernamePasswordAuthenticationFilter.class)
        ;


        http
                // 로그인
                .oauth2Login()                                  // OAuth 2.0 로그인 기능에 대한 여러 설정의 진입점
                    .defaultSuccessUrl("/loginSuccess")         // 로그인 성공 시, 이동 할 URL
                    .failureUrl("/loginFailure")                // 로그인 실패 시, 이동 할 URL
                    .userInfoEndpoint()                         // 로그인 성공 후, 사용자 정보를 가져올 떄의 설정
                        .userService(customOAuth2UserService)   // 로그인 성공 후, 후속 조치를 진행 할 UserService 인터페이스 구현체 (리소스 서버에서 받아온 사용자 정보를 핸들링)
        .and()
        .and()
                // 예외
                .exceptionHandling()
                    .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
        .and()

                // 로그아웃
                .logout()
                    .logoutUrl("/logout")
                    .logoutSuccessUrl("/")          // 로그아웃 성공 시, 이동 할 URL
                    .deleteCookies("JSESSIONID")    // 쿠키 삭제
                    .invalidateHttpSession(true)
        ;
    }
}