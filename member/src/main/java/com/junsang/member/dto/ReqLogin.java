package com.junsang.member.dto;

import com.junsang.member.entity.Members;
import lombok.Data;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

@Data
public class ReqLogin {

    @NotNull(message = "Email cannot be null")
    @Size(min = 4, message = "Email not be less than 4 characters")
    @Email
    private String email;

    @NotNull(message = "Password cannot be null")
    @Size(min = 8, message = "Email not be less than 8 characters")
    private String password;



}
