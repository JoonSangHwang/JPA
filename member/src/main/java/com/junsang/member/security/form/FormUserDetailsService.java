package com.junsang.member.security.form;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

public interface FormUserDetailsService extends UserDetailsService {

    UserDetails loadUserByUsername(String username);
}
