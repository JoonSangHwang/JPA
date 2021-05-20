package com.junsang.member.aop;

import com.junsang.member.security.jwt.JwtController;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;

@Slf4j
@Aspect
@Configuration
public class RunTimeMeasurement {

//    private final Logger logger = LoggerFactory.getLogger(RunTimeMeasurement.class);

    @Pointcut("execution(public * com.junsang.member.security.jwt.JwtController.*(..))")
    private void methodPointCut() {}


    @Before("execution(public * com.junsang.member.security.jwt.JwtController.*(..))")
    public void beforeLog(JoinPoint joinPoint) {
        log.debug("==================== [AspectJ] - [@Before] 메소드명: {} ", joinPoint.getSignature().getName());

        for (Object parameter : joinPoint.getArgs()) {
            log.debug("==================== [AspectJ] - [@Before] 파라미터: {} ", parameter);
        }
    }


    @After("execution(public * com.junsang.member.security.jwt.JwtController.*(..))")
    public void afterLog(JoinPoint joinPoint) {
        log.debug("==================== [AspectJ] - [@After] 메소드명: {} ", joinPoint.getSignature().getName());
    }


    /** 메서드가 예외 없이 성공적으로 끝났을때 호출 **/
    @AfterReturning("execution(public * com.junsang.member.security.jwt.JwtController.*(..))")
    public void afterReturning(JoinPoint joinPoint
//            , Object obj
    ) {
        log.debug("==================== [AspectJ] - [@AfterReturning] 메서드명: {} ", joinPoint.getSignature().getName());
//        log.debug("==================== [AspectJ] - [@AfterReturning] 리턴결과: {}", obj);
    }


    /** 메서드 실행 중 예외 발생 시, 호출 **/
    @AfterThrowing(value = "methodPointCut()", throwing="ex")
    public void afterThrowing(JoinPoint joinPoint, Exception ex) {
        log.debug("==================== [AspectJ] - [@AfterThrowing] 메서드명: {} ", joinPoint.getSignature().getName());
        log.debug("==================== [AspectJ] - [@AfterThrowing] Exception: {} ", ex.getMessage());
    }


    /** 메서드 실행 전/후 호출 **/
    @Around("execution(public * com.junsang.member.security.jwt.JwtController.*(..))")
    public Object aroundLog(ProceedingJoinPoint joinPoint) {

        // Start 시간
        long startTime = System.currentTimeMillis();

        Object result = null;
        try {
            result = joinPoint.proceed();
        } catch (Throwable e) {
            e.printStackTrace();
        } finally {
            log.debug("==================== [AspectJ] - [@Around] 메서드명: {} ", joinPoint.getSignature().getName());


            // 파라미터
            Object[] args = joinPoint.getArgs();
            for (Object obj : args) {
                log.debug("==================== [AspectJ] - [@Around] 파라미터: {} ", obj.toString());
            }


            // End 시간
            long duringTime = System.currentTimeMillis() - startTime;
            log.debug("==================== [AspectJ] - [@Around] Time Taken by {} is {} ", joinPoint, duringTime);
        }

        return result;
    }

}
