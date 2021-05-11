package com.junsang.member.dto;

import lombok.Builder;
import lombok.Data;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

@Data
public class SignupDto {

//    @NotNull(message = "Username cannot be null")
//    @Size(min = 2, max = 20, message = "Username must be at least 4 characters and at most 6 characters")
    private String username;

//    @NotNull(message = "Email cannot be null")
//    @Size(min = 4, message = "Email not be less than 4 characters")
//    @Email
    private String email;

//    @NotNull(message = "Password cannot be null")
//    @Size(min = 8, message = "Email not be less than 8 characters")
    private String password;

//    @Size(min = 2, max = 2, message = "joinCd must be 2 characters")
    private String joinCd;



    // 가입코드
    // 생성자
    // 생성일
    // 수정자
    // 수정일
}
