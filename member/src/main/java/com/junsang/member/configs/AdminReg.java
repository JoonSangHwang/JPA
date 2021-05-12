package com.junsang.member.configs;

import com.junsang.member.dto.ResLogin;
import com.junsang.member.entity.Members;
import com.junsang.member.repository.MemberRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

@Component
public class AdminReg {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Bean
    public CommandLineRunner runner(MemberRepository memberRepository) {
        return (args) -> {
            Members member = Members.builder()
                    .username("준상")
                    .password(passwordEncoder.encode("1234"))
                    .email("gufrus@naver.com")
                    .joinCd("01")
                    .lastLoginDt(LocalDateTime.now())
                    .build();

            memberRepository.save(member);

        };
    }
}
