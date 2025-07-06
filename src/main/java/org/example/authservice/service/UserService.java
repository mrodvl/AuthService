package org.example.authservice.service;


import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.example.authservice.dto.AuthentificationResponseToken;
import org.example.authservice.dto.UserAuthDTO;
import org.example.authservice.dto.UserRegDTO;
import org.example.authservice.entity.User;

/**
 * Интерфейс сервиса для обработки операций, связанных с пользователем,
 * включая регистрацию, аутентификацию и управление токенами.
 */

public interface UserService {
    /**
     * Регистрирует нового пользователя в системе и генерирует токены аутентификации.
     *
     * @param userRegDTO объект передачи данных, содержащий данные регистрации пользователя
     * @return an {@link AuthentificationResponseToken}, содержащий токены доступа и обновления
     */
    AuthentificationResponseToken registrationUser(UserRegDTO userRegDTO);


    User getUserById(long id);
    User getUserByName(String name);

    /**
     * Аутентифицирует пользователя и генерирует токены JWT.
     *
     * @param userAuthDTO объект передачи данных, содержащий учетные данные пользователя
     * @return an {@link AuthentificationResponseToken}, содержащий токены доступа и обновления
     */
    AuthentificationResponseToken authUser(UserAuthDTO userAuthDTO);

    /**
     * Обновляет токен доступа JWT с помощью токена обновления.
     *
     * @param httpResponse HTTP-ответ для отправки
     * @param httpRequest HTTP-запрос, содержащий токен обновления
     * @return {@link AuthentificationResponseToken}, содержащий обновленные токены доступа и обновления
     */
    AuthentificationResponseToken refreshToken(HttpServletResponse httpResponse, HttpServletRequest httpRequest);

}