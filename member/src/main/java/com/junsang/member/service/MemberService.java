package com.junsang.member.service;

import com.junsang.member.dto.SignupDto;
import com.junsang.member.entity.Members;

public interface MemberService {

    void createUser(Members member);
}
