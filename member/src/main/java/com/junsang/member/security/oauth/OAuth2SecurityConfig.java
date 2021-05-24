package com.junsang.member.security.oauth;

import com.junsang.member.security.jwt.JwtFilter;
import com.junsang.member.security.jwt.JwtProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static com.junsang.member.entity.enumType.RoleType.*;

@Configuration
@EnableWebSecurity      // 시큐리티 활성화
@Order(30)
public class OAuth2SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private CustomOAuth2UserService customOAuth2UserService;

    private JwtProvider jwtProvider;

    public OAuth2SecurityConfig(JwtProvider jwtProvider) {
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


        /** OAuth **/
        http
                .authorizeRequests()                                      // 요청에 의한 보안검사 시작
                .antMatchers("/").permitAll()                   // [페이지] index
                .antMatchers("/mainPage").permitAll()           // [페이지] 메인
                .antMatchers("/loginPage").permitAll()          // [페이지] 로그인
                .antMatchers("/signUpPage").permitAll()         // [페이지] 회원가입

                .antMatchers("/signUp").permitAll()

                .antMatchers("/loginRequest").permitAll()
                .and()

                // 정책
                .authorizeRequests()
                .antMatchers("/facebook").hasAuthority(FACEBOOK.getRoleType())
                .antMatchers("/google").hasAuthority(GOOGLE.getRoleType())
                .antMatchers("/kakao").hasAuthority(KAKAO.getRoleType())

        .and()
                // 로그인
                .oauth2Login()                              // OAuth 2.0 로그인 기능에 대한 여러 설정의 진입점
                .defaultSuccessUrl("/loginSuccess")         // 로그인 성공 시, 이동 할 URL
                .failureUrl("/loginFailure")                // 로그인 실패 시, 이동 할 URL
                .userInfoEndpoint()                         // 로그인 성공 후, 사용자 정보를 가져올 떄의 설정
                .userService(customOAuth2UserService)        // 로그인 성공 후, 후속 조치를 진행 할 UserService 인터페이스 구현체 (리소스 서버에서 받아온 사용자 정보를 핸들링)
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
//        .and()
//                .authorizeRequests()
//                .anyRequest().authenticated()
                .and()
                .addFilterBefore(new JwtFilter(jwtProvider), UsernamePasswordAuthenticationFilter.class)
        ;
    }
}
