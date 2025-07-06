package org.example.authservice.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
/**
 * Объект передачи данных (DTO) для представления токенов аутентификации.
 * Содержит токен доступа (accessToken) и токен обновления (refreshToken),
 * возвращаемые в ответ на запросы аутентификации или регистрации
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class AuthentificationResponseToken {
    private String accessToken;
    private String refreshToken;

}
