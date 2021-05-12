package com.junsang.member.security.ajax;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

@Component
public class AjaxWebConfig {

    @Bean
    public AuthenticationSuccessHandler ajaxSuccessHandler(){
        return new AjaxSuccessHandler();
    }

    @Bean
    public AuthenticationFailureHandler ajaxFailureHandler(){
        return new AjaxFailureHandler();
    }

    @Bean
    public AuthenticationProvider ajaxProvider() {
        return new AjaxProvider();
    }
}
