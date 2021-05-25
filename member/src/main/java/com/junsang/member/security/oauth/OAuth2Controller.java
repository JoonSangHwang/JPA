package com.junsang.member.security.oauth;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OAuth2Controller {

    @GetMapping("/loginSuccess")
    public String loginSuccess() {
        System.out.println("OAuth 2.0 complete !!!!!!!");
        return "redirect:/board/list";
    }


    @GetMapping("/ipa/tt2")
    public String tt2() {
        System.out.println("OAuth 2.0 complete !!!!!!!");
        return "redirect:/board/list";
    }
}
