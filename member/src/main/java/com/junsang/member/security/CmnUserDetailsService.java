package com.junsang.member.security;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

public interface CmnUserDetailsService extends UserDetailsService {

    UserDetails loadUserByUsername(String username);
}
