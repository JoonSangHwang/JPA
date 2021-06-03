package com.junsang.member.security;

import com.junsang.member.dto.ResLogin;
import com.junsang.member.exception.UserIdNotFoundException;
import com.junsang.member.repository.MemberRepository;
import com.junsang.member.security.exception.LoginStepException;
import com.junsang.member.security.exception.ErrorCode;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.persistence.NonUniqueResultException;
import java.util.ArrayList;

@Service
public class CmnUserDetailsServiceImpl implements CmnUserDetailsService {

    @Autowired
    private MemberRepository memberRepository;

    @Autowired
    private ModelMapper modelMapper;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {

        long userInfoCnt = memberRepository.selectUserCount(email);
        if (userInfoCnt == 0)
            throw new LoginStepException("테스트");
        else if (userInfoCnt == 2)
            throw new NonUniqueResultException("해당 메일(" + email + ")의 검색 결과가 2가지 이상입니다. 관리자에게 문의해주세요");

        ResLogin userInfo = memberRepository.selectUser(email);
        if (userInfo == null)
            throw new UserIdNotFoundException("존재하지 않는 이메일 입니다");

        // 비밀번호


        return new User( userInfo.getEmail()
                            , userInfo.getPassword()
                            , true                  // 사용자가 활성화 된 경우 true
                            , true          // 계정이 만료되지 않은 경우 true
                            , true        // 자격 증명이 만료되지 않은 경우 true
                            , true          // 계정이 잠겨 있지 않은 경우 true
                            , new ArrayList<>());
    }
}
