package com.junsang.member.security.service;

import com.junsang.member.dto.ReqLogin;
import com.junsang.member.dto.ResLogin;
import com.junsang.member.entity.Members;
import com.junsang.member.exception.UserIdNotFoundException;
import com.junsang.member.repository.MemberRepository;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class CustomUserDetailsServiceImpl implements CustomUserDetailsService {

    @Autowired
    private MemberRepository memberRepository;

    @Autowired
    private ModelMapper modelMapper;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {

        ResLogin userInfo = memberRepository.selectUser(email);
        if (userInfo == null)
            throw new UserIdNotFoundException("존재하지 않는 이메일 입니다");

        User user = new User( userInfo.getEmail()
                            , userInfo.getPassword()
                            , true
                            , true
                            , true
                            , true
                            , new ArrayList<>());
        return user;
    }
}
