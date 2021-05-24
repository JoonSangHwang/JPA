package com.junsang.member.security.jwt;

import com.junsang.member.security.jwt.exception.ErrorCode;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
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

    private final int standardTimeForReissuanceOfAccessToken = 10;
    private final int standardTimeForReissuanceOfRefreshToken = 10;






    /**
     * InitializingBean 클래스의 afterPropertiesSet() 메소드 오버라이딩
     *
     * -> secretKey 를 Base64로 인코딩
     * -> Key 값 초기화를 위해 afterPropertiesSet() 사용
     *
     * -> JWT 는 Claim 을 Json 형태로 표현한 것으로, Claim Json 문자열이 BASE64 인코딩을 통해 요청을 할 수 있다.
     *    암호를 풀기 위해 secretKey 역시 BASE64 로 인코딩 해준다.
     * -> BASE64(HS512암호화(lowSig))
     */
    @Override
    public void afterPropertiesSet() throws Exception {
        byte[] keyBytes = Decoders.BASE64.decode(jwtTokenSecret);
        this.key = Keys.hmacShaKeyFor(keyBytes);        // 무결성을 위해 HMAC 사용
    }



    /**
     * Auth 객체의 권한정보를 이용해 토큰 생성 후, 리턴
     */
    public String createToken(Authentication auth) {
        Map<String, Object> headers = new HashMap<>();
        headers.put("js_header", "JS Header");

        Map<String, Object> payloads = new HashMap<>();
        payloads.put("email", auth.getName());
//        payloads.put("password", "1234");

        String subject  = "용도는 인증";
        String issuer   = "발급자는 준상";
        String audience = "대상자는 미정";

        // 토큰 생성
        return Jwts
                .builder()
                .setHeader(headers)             // Headers 설정
                .setClaims(payloads)            // Claims 설정
                .setSubject(subject)
                .setIssuer(issuer)
                .setAudience(audience)
                .setExpiration(new Date(System.currentTimeMillis() + Long.parseLong(jwtTokenExpirationTime)))
                .setNotBefore(new Date(System.currentTimeMillis()))     // 토큰 활성 시간
                .setIssuedAt(new Date(System.currentTimeMillis()))      // 토큰 발급 시간
                .signWith(key, SignatureAlgorithm.HS512)                // HS512와 Key 로 Sign 서명
                .compact();                                             // 토큰 생성
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
    public String validateToken(String token) {
        String result = "";

        try {
            Jwts
                    .parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token);     // 파싱 및 검증, 실패 시 에러
            return result;
        } catch (SecurityException | MalformedJwtException e) {
            logger.debug("잘못된 JWT 서명 입니다.");
            result = "INVALID_TOKEN";
        } catch (ExpiredJwtException e) {
            logger.debug("만료된 JWT 토큰 입니다.");
            result = "EXPIRED_TOKEN";
        } catch (UnsupportedJwtException e) {
            logger.debug("지원되지 않는 JWT 서명 입니다.");
            result = "UNSUPRT_TOKEN";
        } catch (IllegalArgumentException e) {
            logger.debug("JWT 토큰이 잘 못 되었습니다.");
            result = "ILLEGAL_TOKEN";
        }
//        catch (Exception e) {
//            logger.debug("JWT 오류 입니다.");
//            result = "EXCPTIN_TOKEN";
//        }

        return result;
    }

    // 토큰의 유효성 + 만료일자 확인
    public boolean getTokenExpiration(String jwtToken) {
        try {
            Jws<Claims> claims = Jwts
                    .parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(jwtToken);


            logger.debug("[JS LOG] 현재 토큰의 만료 설정 값: " + claims.getBody().getExpiration());
            boolean tokenExpirationYn = !claims.getBody().getExpiration().before(new Date());

            if (tokenExpirationYn)
                logger.debug("[JS LOG] 현재 토큰의 만료 기간이 지났습니다.");

            return tokenExpirationYn;
        } catch (Exception e) {
            return false;
        }
    }

    // 토큰에서 회원 정보 추출
    public Claims getTokenData(String jwtToken) {
        return Jwts
                .parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(jwtToken)
                .getBody();
    }


    /**
     * Access Token 의 만료 일자를 보고 재발급 해주어야 하는지 체크
     *
     * @return  true  재발급 받아야함
     */
    public boolean whetherTheTokenIsReissued(String accessToken) {
        Claims contents = Jwts
                .parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(accessToken)
                .getBody();

        Date curTime = new Date(System.currentTimeMillis());
        Date curExpirationTime = contents.getExpiration();

        long diff = curExpirationTime.getTime() - curTime.getTime();
        long min = diff / (1000 * 60);  // 분으로 계산

        System.out.println("현재 시각: " + curTime.getTime());
        System.out.println("현재 시각: " + curExpirationTime.getTime());


        // 10분 이하
        if (standardTimeForReissuanceOfAccessToken <= min)
            return false;

        return true;
    }

}