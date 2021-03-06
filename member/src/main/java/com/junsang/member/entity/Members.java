package com.junsang.member.entity;

import com.junsang.member.entity.enumType.RoleType;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "TB_MEMBER_MASTER")
@Builder
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
public class Members {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(nullable=false)
    private Long seq;                   // 시퀀스

    @Column(name = "NM", nullable=false)
    private String username;            // 이름

    @Column(name = "pw", nullable=true)
    private String password;            // 패스워드

    @Column(nullable=false)
    private String email;               // 이메일

    @Column(nullable=false, columnDefinition="char", length=2)
    private String joinCd;              // 가입 코드

    @Column(nullable=true)
    private LocalDateTime lastLoginDt;  // 마지막 로그인 일자

    @Enumerated(EnumType.STRING)
    @Column
    private RoleType roleType;

    @Column
    private String picture;

    public String getRoleType() {
        return roleType.getRoleType();
    }


    public Members update(String username, String picture) {
        this.username = username;
        this.picture = picture;

        return this;
    }
}
