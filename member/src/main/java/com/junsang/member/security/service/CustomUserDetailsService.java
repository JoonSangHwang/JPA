package com.junsang.member.security.service;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

//@Service
public interface CustomUserDetailsService extends UserDetailsService {

    UserDetails loadUserByUsername(String username);
}
