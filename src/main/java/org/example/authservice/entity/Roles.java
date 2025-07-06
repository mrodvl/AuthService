package org.example.authservice.entity;


import org.springframework.security.core.authority.SimpleGrantedAuthority;
import java.util.ArrayList;
import java.util.List;

/**
 * Перечисление ролей пользователей в системе
 * Определяет доступные роли (USER, ADMIN) и предоставляет метод для получения списка полномочий
 */
public enum Roles {
    USER, ADMIN;

    public List<SimpleGrantedAuthority> grantedAuthorityList(){
        List<SimpleGrantedAuthority> grantedAuthorityList = new ArrayList<>();
        for (Roles value : Roles.values()) {
            grantedAuthorityList.add(new SimpleGrantedAuthority("ROLE_" + value.name()));
        }
        return grantedAuthorityList;
    }

}
