package org.example.authservice.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.example.authservice.dto.AuthentificationResponseToken;
import org.example.authservice.dto.UserAuthDTO;
import org.example.authservice.dto.UserRegDTO;
import org.example.authservice.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST-контроллер для обработки запросов, связанных с аутентификацией.
 * Предоставляет эндпоинты для регистрации, входа и проверки токена.
 */

@AllArgsConstructor
@RestController
@RequestMapping("/api/v1")
public class AuthController {
    private final UserService userService;

    /**
     * Регистрирует нового пользователя в системе.
     *
     * @param userRegDTO объект, содержащий данные регистрации пользователя
     * @return {@link ResponseEntity}, содержащий ответ аутентификации с токенами доступа
     */
    @PostMapping("/reg")
    public ResponseEntity<AuthentificationResponseToken> reg(@RequestBody UserRegDTO userRegDTO) {
        AuthentificationResponseToken authentificationResponseToken =
                userService.registrationUser(userRegDTO);

        return ResponseEntity.ok(authentificationResponseToken);
    }


    /**
     * Аутентифицирует пользователя и генерирует токен JWT.
     *
     * @param userAuthDTO объект, содержащий учетные данные пользователя
     * @return {@link ResponseEntity}, содержащий ответ аутентификации с токенами доступа и обновления
     */

    @PostMapping("/auth")
    public ResponseEntity<AuthentificationResponseToken> auth (@RequestBody UserAuthDTO userAuthDTO) {
        AuthentificationResponseToken authentificationResponseToken =
                userService.authUser(userAuthDTO);

        return ResponseEntity.ok(authentificationResponseToken);
    }


    /**
     * Обновляет токен доступа JWT
     *
     * @param request HTTP-запрос, содержащий токен обновления
     * @param response HTTP-ответ для отправки
     * @return {@link ResponseEntity}, содержащий новый ответ аутентификации с обновленными токенами
     */
    @PostMapping("/refresh")
    public ResponseEntity<AuthentificationResponseToken> refreshToken (
            HttpServletRequest request,
            HttpServletResponse response) {

      return ResponseEntity.ok(userService.refreshToken(response,request));
    }

}
