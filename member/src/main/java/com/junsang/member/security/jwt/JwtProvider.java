package com.junsang.member.security.jwt;

import com.junsang.member.entity.TokenEntity;
import com.junsang.member.repository.TokenRepository;
import com.junsang.member.security.jwt.exception.ErrorCode;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
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

    private final int standardTimeForReissuanceOfAccessToken = 10;
    private final int standardTimeForReissuanceOfRefreshToken = 10;


    @Autowired
    private TokenRepository tokenRepository;




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
        Claims contents = Jwts
                .parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();

        String email = "gufrus@naver.com";
        String pw = "1234";

        return new UsernamePasswordAuthenticationToken(
                email,
                pw,
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
            logger.info("잘못된 JWT 서명 입니다.");
            result = "INVALID_TOKEN";
        } catch (ExpiredJwtException e) {
            logger.info("만료된 JWT 토큰 입니다.");
            result = "EXPIRED_TOKEN";
        } catch (UnsupportedJwtException e) {
            logger.info("지원되지 않는 JWT 서명 입니다.");
            result = "UNSUPRT_TOKEN";
        } catch (IllegalArgumentException e) {
            logger.info("JWT 토큰이 잘 못 되었습니다.");
            result = "ILLEGAL_TOKEN";
        }
//        catch (NullPointerException e) {
//            logger.info("JWT 토큰이 존재하지 않습니다.");
//            result = "NON_LOGIN";
//        } catch (Exception e) {
//            logger.info("JWT 오류 입니다.");
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

    public String getTokenUUID(String jwtToken) {
        Claims contents = Jwts
                .parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(jwtToken)
                .getBody();

        return (String) contents.get("uuid");
    }


    /**
     * 토큰의 만료 일자를 확인하여 만기 일자가 가깝다면, 재발급
     *
     * @return true: 정상 / false: 재발행
     */
    public boolean isReissued(String accessToken) {
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

        // 재발행 여부
        return standardTimeForReissuanceOfAccessToken > min;
    }

    public String createToken(Authentication auth, String uuid) {
        Map<String, Object> headers = new HashMap<>();
        headers.put("js_header", "JS Header");

        Map<String, Object> payloads = new HashMap<>();
        payloads.put("email", auth.getName());
        payloads.put("uuid", uuid);

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
     * JWT 토큰의 Payload 검증
     *
     * @param reqToken      토큰 값
     * @param tokenType     토큰 구분 값
     */
    public boolean payLoadValid(String reqToken, String tokenType) {

        // 토큰 속의 UUID 가져오기
        String tokenUUID = getTokenUUID(reqToken);
        if (tokenUUID == null)
            return false;

        // 토큰 검색
        TokenEntity tokenEntity = tokenSearchInCache(tokenUUID);
        if (tokenEntity == null)
            return false;

        // 사용 가능한 토큰인지 체크
        String tokenUsable = tokenEntity.getUsableYn();
        if ("N".equals(tokenUsable))
            return false;

        // 현재 요청 토큰과 캐시에 존재하는 토큰이 같은지 검증
        String tokenVal = "ACCESS".equals(tokenType)
                ? tokenEntity.getAccessToken()
                : tokenEntity.getRefreshToken();
        return reqToken.equals(tokenVal);
    }


    /**
     * 캐시(Redis)에 저장 되어 있는 JWT 토큰 검색
     *
     * @param uuid          UUID in Token
     */
    @Cacheable(key = "#uuid", value = "memberAuth")
    public TokenEntity tokenSearchInCache(String uuid) {
        return tokenRepository
                .findById(uuid)
                .orElse(null);
    }

    /**
     * 캐시(Redis)에 JWT 토큰 저장
     *
     * @param accessToken       접근 토큰
     * @param refreshToken      갱신 토큰
     * @param uuid              토큰 판별 값
     */
    @Cacheable(key = "#uuid", value = "memberAuth")
    public void tokenSaveInCache(String accessToken, String refreshToken, String uuid) {
        TokenEntity tokenEntity = TokenEntity.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .uuid(uuid)
                .usableYn("Y")
                .build();

        tokenRepository.save(tokenEntity);
    }
}