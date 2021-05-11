package com.junsang.member.service.impl;

import com.junsang.member.entity.Members;
import com.junsang.member.repository.MemberRepository;
import com.junsang.member.service.MemberService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class MemberServiceImpl implements MemberService {

    @Autowired
    private MemberRepository memberRepository;

    @Override
    public void createUser(Members member) {
        memberRepository.save(member);
    }
}
