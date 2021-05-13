package com.junsang.member.security.form;

import com.junsang.member.security.form.FormProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.*;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@Component
public class FormWebConfig {

    @Autowired
    private PasswordEncoder passwordEncoder;

    /**
     * Bean AuthenticationProvider
     */
    @Bean
    public AuthenticationProvider formProvider() {
        return new FormProvider(passwordEncoder);
    }







}
