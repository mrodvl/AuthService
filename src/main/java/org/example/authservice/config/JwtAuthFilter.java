package org.example.authservice.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.example.authservice.repo.TokenRepository;
import org.example.authservice.service.JwtService;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Фильтр для аутентификации запросов с использованием JWT-токенов.
 * Проверяет наличие и валидность JWT-токена в заголовке запроса, аутентифицирует пользователя
 * и устанавливает контекст безопасности для защищенных запросов.
 */
@Component
@RequiredArgsConstructor

public class JwtAuthFilter extends OncePerRequestFilter {
    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    private final TokenRepository tokenRepository;

    /**
     * Обрабатывает входящий HTTP-запрос, проверяя наличие и валидность JWT-токена.
     * Если токен действителен, устанавливает аутентификацию в контексте безопасности.
     * Пропускает запросы к эндпоинтам /api/v1/auth и /api/v1/reg без проверки.
     *
     * @param request     HTTP-запрос, содержащий заголовок Authorization с JWT-токеном
     * @param response    HTTP-ответ, используемый для обработки запроса
     * @param filterChain цепочка фильтров для продолжения обработки запроса
     * @throws ServletException если возникает ошибка при обработке запроса
     * @throws IOException      если возникает ошибка ввода-вывода
     * @throws IllegalStateException если токен отсутствует или недействителен
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String authorizationHeader = request.getHeader("Authorization");
        String jwtToken;
        String username;

        if (request.getServletPath().contains("/api/v1/auth")) {
            filterChain.doFilter(request, response);
            return;
        }

        if (request.getServletPath().contains("/api/v1/reg")) {
            filterChain.doFilter(request, response);
            return;
        }


        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            throw new IllegalStateException("token not found OR token is Valid");
        }



        jwtToken = authorizationHeader.substring(7);
        username = jwtService.extractUsername(jwtToken);

        // Проверка валидности токена
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            //проверка валидности токена
            boolean isTokenValid = tokenRepository.findByToken(jwtToken)
                    .map(t -> !t.isExpired() && !t.isRevoked())
                    .orElse(false);

            if (jwtService.isValidToken(jwtToken, userDetails) && isTokenValid) {
                UsernamePasswordAuthenticationToken authenticationToken =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext()
                        .setAuthentication(authenticationToken);
            }
        }

        filterChain.doFilter(request,response);

    }
}
