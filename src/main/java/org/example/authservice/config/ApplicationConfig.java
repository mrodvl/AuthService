package org.example.authservice.config;


import lombok.RequiredArgsConstructor;
import org.example.authservice.repo.UserRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
/**
 * Конфигурационный класс для настройки компонентов аутентификации Spring Security.
 * Определяет бины для сервиса пользователей, провайдера аутентификации, кодировщика паролей
 * и менеджера аутентификации.
 */
@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {
    private final UserRepository userRepository;

    /**
     * Создает сервис для загрузки данных пользователя по имени пользователя.
     *
     * @return объект {@link UserDetailsService}, который загружает данные пользователя из репозитория
     * @throws UsernameNotFoundException если пользователь с указанным именем не найден
     */
    @Bean
    public UserDetailsService userDetailsService() {
        return username -> userRepository.findByUsername(username)
                .orElseThrow(()-> new UsernameNotFoundException("User not found"));
    }

    /**
     * Создает провайдер аутентификации, использующий сервис пользователей и кодировщик паролей.
     *
     * @return объект {@link AuthenticationProvider} для выполнения аутентификации
     */
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService());
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    /**
     * Создает кодировщик паролей, использующий алгоритм BCrypt.
     *
     * @return объект {@link PasswordEncoder} для хеширования и проверки паролей
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Создает менеджер аутентификации на основе предоставленной конфигурации.
     *
     * @param configuration конфигурация аутентификации Spring Security
     * @return объект {@link AuthenticationManager} для управления процессом аутентификации
     * @throws Exception если возникает ошибка при получении менеджера аутентификации
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return   configuration.getAuthenticationManager();
    }
}
