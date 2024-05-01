package com.weektwit.auth.wrapper;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserInfoWrapper {
    private String email;
    private String firstName;
    private String lastName;
    private String accessToken;
    private String refreshToken;
}
