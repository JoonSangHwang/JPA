package com.junsang.member.controller;

import com.junsang.member.dto.SignupDto;
import com.junsang.member.entity.Members;
import com.junsang.member.service.MemberService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

import java.time.LocalDate;
import java.time.LocalDateTime;

@Controller
public class LoginController {

    @Autowired
    private MemberService memberService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @RequestMapping(value = "/loginPage")
    public String login(){
        return "login/loginPage";
    }

    @GetMapping("/loginSuccess")
    public String loginSuccess() {
        System.out.println("OAuth 2.0 complete !!!!!!!");
        return "redirect:/board/list";
    }


    @GetMapping(value = "/signUpPage")
    public String signUp() {
        return "login/signUpPage";
    }


    /**
     * 회원 가입
     */
    @PostMapping("/signUp")
    public String createUser(@RequestBody SignupDto signupDto) {

        // 데이터 바인딩
        Members member = Members.builder()
                .username(signupDto.getUsername())
                .password(passwordEncoder.encode(signupDto.getPassword()))
                .email(signupDto.getEmail())
                .joinCd("01")
                .lastLoginDt(LocalDateTime.now())
                .build();

        // 저장
        memberService.createUser(member);

        return "redirect:/";
    }

}
