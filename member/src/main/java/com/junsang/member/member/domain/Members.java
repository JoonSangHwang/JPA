package com.junsang.member.member.domain;

import javax.persistence.*;

@Entity
@Table(name = "TB_MEMBER_MASTER")
public class Members {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column private Long SEQ;
}
