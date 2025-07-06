package org.example.authservice.repo;

import org.example.authservice.entity.Token;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
/**
 * Интерфейс для работы с данными класса Token
 * findByToken ищет токен по строковому значению и обрабатывается Optional в избежании NullPointerException
 * Метод findAllValidTokensByUserId проверяет все действующие токены пользователя по ID
 */
@Repository
public interface TokenRepository extends JpaRepository<Token, Long> {
    Optional<Token> findByToken(String token);

    /**
     * Находит все действующие токены для пользователя с указанным идентификатором.
     * Возвращает токены, которые не истекли (expired = false) и не были отозваны (revoked = false).
     *
     * @param user_id идентификатор пользователя
     * @return список объектов {@link Token}, соответствующих действующим токенам пользователя
     */
    @Query("""
           SELECT t from Token t 
           inner join User u on t.user.id = u.id 
           where u.id = :user_id and (t.expired = false or t.revoked = false)
            """)
    List<Token> findAllValidTokensByUserId(Long user_id);
}
