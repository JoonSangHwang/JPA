package com.junsang.member.security.oauth;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target(ElementType.PARAMETER)              // 어노테이션이 생성 될 수 있는 위치 - 파라미터
@Retention(RetentionPolicy.RUNTIME)         // 컴파일 이후에도 JVM에 의해서 참조가 가능하다.
public @interface SocialUser {
}