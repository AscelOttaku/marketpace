package com.market.helper.objectcreator;

import com.market.dto.request.auth.UserRegisterRequest;
import com.market.dto.request.auth.UserUpdateRequest;
import com.market.model.Account;
import com.market.model.User;

public interface UserManagementObjectCreator extends ObjectCreator{
    User createUserSaveModel(UserRegisterRequest request);
    User createUserUpdateModel(User existingUser, UserUpdateRequest request);

    Account createAccountSaveModel(User user);
}
