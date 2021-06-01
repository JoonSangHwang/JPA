package com.junsang.member.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;

@RedisHash("memberAuth")
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TokenEntity {

    @Id
    private String uuid;
    private String accessToken;
    private String refreshToken;
    private String usableYn;

    public void usableUpdate(String flag) {
        this.usableYn = flag;
    }
}