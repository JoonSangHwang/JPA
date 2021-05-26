package com.junsang.member.security.oauth;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.util.Map;

@RestController
public class OAuth2Controller {

    @GetMapping("/loginSuccess")
    @ResponseBody
    public String loginSuccess() {
        System.out.println("OAuth 2.0 complete !!!!!!!");
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();


        if (principal instanceof DefaultOAuth2User) {
            String myAccessToken = (String) ((DefaultOAuth2User) principal).getAttributes().get("myAccessToken");
            String myRefreshToken = (String) ((DefaultOAuth2User) principal).getAttributes().get("myRefreshToken");

        }

        return "redirect:/board/list";
    }


    @GetMapping("/ipa/tt2")
    public String tt2() {
        System.out.println("OAuth 2.0 complete !!!!!!!");
        return "redirect:/board/list";
    }
}
