package com.denghui.springbootinit.service;

import com.denghui.springbootinit.model.entity.User;
import com.baomidou.mybatisplus.extension.service.IService;
import com.denghui.springbootinit.model.vo.LoginUserVO;

/**
 * <p>
 * 用户 服务类
 * </p>
 *
 * @author denghui
 * @since 2024-05-10
 */
public interface IUserService extends IService<User> {

    /**
     * 获取当前登录用户
     *
     * @return {@link User}
     */
    User getLoginUser();


    /**
     * 用户注册
     *
     * @param userAccount   用户账户
     * @param userPassword  用户密码
     * @param checkPassword 校验密码
     * @return 新用户 id
     */
    long userRegister(String userAccount, String userPassword, String checkPassword);

    /**
     * 用户登录
     *
     * @param userAccount  用户账户
     * @param userPassword 用户密码
     * @return 脱敏后的用户信息
     */
    LoginUserVO userLogin(String userAccount, String userPassword);
}
