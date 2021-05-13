package com.junsang.member.security.form;

import com.junsang.member.dto.ResLogin;
import com.junsang.member.exception.UserIdNotFoundException;
import com.junsang.member.repository.MemberRepository;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.persistence.NonUniqueResultException;
import java.util.ArrayList;

@Service
public class FormUserDetailsServiceImpl implements FormUserDetailsService {

    @Autowired
    private MemberRepository memberRepository;

    @Autowired
    private ModelMapper modelMapper;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {

        long userInfoCnt = memberRepository.selectUserCount(email);
        if (userInfoCnt != 1)
            throw new NonUniqueResultException("해당 메일(" + email + ")의 검색 결과가 2가지 이상입니다. 관리자에게 문의해주세요");

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
