package com.junsang.member.exception;

public class UserIdNotFoundException extends RuntimeException {

    public UserIdNotFoundException(String msg) {
        super(msg);
    }
}
