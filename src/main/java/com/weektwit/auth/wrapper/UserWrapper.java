package com.weektwit.auth.wrapper;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserWrapper extends UserCredentialsWrapper {
    private String firstName;
    private String lastName;
}
