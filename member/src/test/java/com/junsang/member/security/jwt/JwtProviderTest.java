package com.junsang.member.security.jwt;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest
class JwtProviderTest {

    @Autowired
    JwtProvider jwtProvider;

    @Test
    @DisplayName("토큰 생성하기")
    public void 토큰_생성하기() {
//        String token = jwtProvider.createToken();
//        System.out.println(">>>>>>>>>>>>>> token = " + token);
    }

    @Test
    @DisplayName("토큰 검증하기")
    public void 토큰_검증하기() {
//        String token = jwtProvider.createToken();
//        System.out.println(token);
//        jwtProvider.validToken(token);
    }

    @Test
    @DisplayName("토큰 만료시간 따른 재발급 여부 판단: true 일 경우, 재발급 받아야함")
    public void 토큰_만료시간에_따른_재발급_여부_판단() {

        String jwtTokenSecret = "GenerateTemporarykeyValuesForTesting00000000000000000000000000000000000000000000000000000000000";
        byte[] keyBytes = Decoders.BASE64.decode(jwtTokenSecret);
        Key key = Keys.hmacShaKeyFor(keyBytes);
        String jwtTokenExpirationTime = "60";

        String jwtToken = Jwts
                .builder()
                .setExpiration(new Date(System.currentTimeMillis() + Long.parseLong(jwtTokenExpirationTime)))
                .signWith(Keys.hmacShaKeyFor(jwtTokenSecret.getBytes(StandardCharsets.UTF_8)), SignatureAlgorithm.HS512)                // HS512와 Key 로 Sign 서명
                .compact();

        boolean tc1 = jwtProvider.checkTokenReissuanceYN(jwtToken);
        assertTrue(tc1);
    }

    public SecretKey generalKey(){
        String stringKey = Global.JWT_SECRET;
        byte[] encodedKey =Base64.decodeBase64(stringKey);
        SecretKey key = new SecretKeySpec(encodedKey, 0, encodedKey.length, "HmacSHA512");
        return key;
    }
}