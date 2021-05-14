package com.junsang.member.security.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
public class JwtProvider implements InitializingBean {

    private final Logger logger = LoggerFactory.getLogger(JwtProvider.class);

    @Value("${token.expiration_time}")
    private String jwtTokenExpirationTime;

    @Value("${token.secret2}")
    private String jwtTokenSecret;

    private Key key;
    private String kkkkey;





    /**
     * InitializingBean 클래스의 afterPropertiesSet() 메소드 오버라이딩
     *
     * -> 객체 초기화, secretKey 를 Base64로 인코딩한다.
     *
     * -> 디코딩한 Key 값을 변수 할당하기 위하여 afterPropertiesSet() 사용
     */
    @Override
    public void afterPropertiesSet() throws Exception {
        byte[] keyBytes = Decoders.BASE64.decode(jwtTokenSecret);
        this.key = Keys.hmacShaKeyFor(keyBytes);
//        this.key = Keys.hmacShaKeyFor(jwtTokenSecret.getBytes());
        System.out.println();
//        kkkkey = Base64.getEncoder().encodeToString(jwtTokenSecret.getBytes());
    }



    /**
     * Auth 객체의 권한정보를 이용해 토큰 생성 후, 리턴
     */
    public String createToken(Authentication auth) {

        String email = (String) auth.getName();
        String token = Jwts.builder()
                .setSubject(email)
                .setExpiration(new Date(System.currentTimeMillis() + Long.parseLong(jwtTokenExpirationTime)))
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();

        return token;
    }

    public String createToken() {
        Map<String, Object> headers = new HashMap<>();
        headers.put("hd", "Test Header");

        Map<String, Object> payloads = new HashMap<>();
        payloads.put("email", "gufrus@naver.com");
        payloads.put("password", "1234");

        return Jwts.builder()
                .setHeader(headers)     // Headers 설정
                .setSubject("Test Subject")     // 토큰 용도
                .setClaims(payloads)    // Claims 설정
                .setExpiration(new Date(System.currentTimeMillis() + Long.parseLong(jwtTokenExpirationTime)))
                .signWith(key, SignatureAlgorithm.HS512)        // HS512와 Key 로 Sign 서명
                .compact();             // 토큰 생성
    }

    /**
     * Token 에 담겨있는 정보를 이용해 Auth 생성 후, 리턴
     */
    public Authentication getAuthentication(String token) {
        // Token 을 이용해 Claim 생성
        Claims claims = Jwts
                .parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();

        return new UsernamePasswordAuthenticationToken(
                claims.get("email"),
                claims.get("password"),
                new ArrayList<>());         // 권한
    }

    /**
     * Token 유효성 검증
     */
    public boolean validateToken(String token) {
        try {
            Jwts
                    .parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token);     // 파싱 및 검증, 실패 시 에러
            return true;
        } catch (SecurityException | MalformedJwtException e) {
            logger.debug("잘못된 JWT 서명 입니다.");
        } catch (ExpiredJwtException e) {
            logger.debug("만료된 JWT 토큰 입니다.");
        } catch (UnsupportedJwtException e) {
            logger.debug("지원되지 않는 JWT 서명 입니다.");
        } catch (IllegalArgumentException e) {
            logger.debug("JWT 토큰이 잘 못 되었습니다.");
        }
        return false;
    }

}
