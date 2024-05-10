package com.denghui.springbootinit.aop;

import com.denghui.springbootinit.annotation.AuthCheck;
import com.denghui.springbootinit.common.ErrorCode;
import com.denghui.springbootinit.exception.BusinessException;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;

import com.denghui.springbootinit.model.enums.UserRoleEnum;
import com.denghui.springbootinit.service.impl.UserServiceImpl;
import org.apache.commons.lang3.StringUtils;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import com.denghui.springbootinit.model.entity.User;
/**
 * 权限校验 AOP
 * # @author denghui
*/

@Aspect
@Component
public class AuthInterceptor {

    @Resource
    private UserServiceImpl userService;
    /*
    *
    * 执行拦截
    *
    * @param joinPoint 加入点
    * @param authCheck 身份验证检查
    * @return {@link Object}
    * @throws Throwable 可投掷
    */

    @Around("@annotation(authCheck)")
    public Object doInterceptor(ProceedingJoinPoint joinPoint, AuthCheck authCheck) throws Throwable {
        String mustRole = authCheck.mustRole();
        RequestAttributes requestAttributes = RequestContextHolder.currentRequestAttributes();
        HttpServletRequest request = ((ServletRequestAttributes) requestAttributes).getRequest();
        // 当前登录用户
        User loginUser = userService.getLoginUser();
        // 必须有该权限才通过
        if (StringUtils.isNotBlank(mustRole)) {
            UserRoleEnum mustUserRoleEnum = UserRoleEnum.getEnumByValue(mustRole);
            if (mustUserRoleEnum == null) {
                throw new BusinessException(ErrorCode.NO_AUTH_ERROR);
            }
            String userRole = loginUser.getUserRole();
            // 如果被封号，直接拒绝
            if (UserRoleEnum.BAN.equals(mustUserRoleEnum)) {
                throw new BusinessException(ErrorCode.NO_AUTH_ERROR);
            }
            // 必须有管理员权限
            if (UserRoleEnum.ADMIN.equals(mustUserRoleEnum)) {
                if (!mustRole.equals(userRole)) {
                    throw new BusinessException(ErrorCode.NO_AUTH_ERROR);
                }
            }
        }
        // 通过权限校验，放行
        return joinPoint.proceed();
    }
}

