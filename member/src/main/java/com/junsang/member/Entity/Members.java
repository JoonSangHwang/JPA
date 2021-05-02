package com.junsang.member.Entity;

import javax.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "TB_MEMBER_MASTER")
public class Members {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(nullable=false)
    private Long seq;                   // 시퀀스

    @Column(nullable=false)
    private String nm;                  // 이름

    @Column(nullable=false)
    private String pw;                  // 패스워드

    @Column(nullable=false)
    private String email;               // 이메일

    @Column(nullable=false, columnDefinition="char", length=2)
    private String joinCd;              // 가입 코드

    @Column(nullable=true)
    private LocalDateTime lastLoginDt;  // 마지막 로그인 일자
}
