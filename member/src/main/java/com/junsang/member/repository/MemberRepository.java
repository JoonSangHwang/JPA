package com.junsang.member.repository;

import com.junsang.member.dto.ReqLogin;
import com.junsang.member.dto.ResLogin;
import com.junsang.member.entity.Members;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface MemberRepository extends JpaRepository<Members, Long> {

    @Query("SELECT  new com.junsang.member.dto.ResLogin(   " +
            "       m.email,                               " +
            "       m.password)                            " +
            "FROM   Members m                              " +
            "WHERE  m.email= :email                        " )
    ResLogin selectUser(@Param("email") String email);
}