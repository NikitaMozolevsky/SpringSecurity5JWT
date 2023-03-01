package com.example.springsecurityreturn.config;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.example.springsecurityreturn.security.JWTUtil;
import com.example.springsecurityreturn.services.PersonDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

//отлов всех запросов и просмотр JWT
@Component
public class JWTFilter extends OncePerRequestFilter {

    private final JWTUtil jwtUtil;
    private final PersonDetailsService personDetailsService;

    @Autowired
    public JWTFilter(JWTUtil jwtUtil, PersonDetailsService personDetailsService) {
        this.jwtUtil = jwtUtil;
        this.personDetailsService = personDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        //this header give JWT
        String authHeader = request.getHeader("Authorization");

        //JWT передается под ключом "Authorization" и начинается после "Bearer "
        if (authHeader!=null && !authHeader.isBlank() && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7 /**Bearer */);

            if (token.isBlank()) { //empty?
                response.sendError(response.SC_BAD_REQUEST,
                        "Invalid token (is blank)");
            } else {
                try {
                    //getting data
                    String username = jwtUtil.validateTokenAndRetrieveClaim(token);
                    UserDetails userDetails = personDetailsService.loadUserByUsername(username);

                    UsernamePasswordAuthenticationToken authenticationToken =
                            new UsernamePasswordAuthenticationToken(
                                    userDetails,
                                    userDetails.getPassword(),
                                    userDetails.getAuthorities());
                    //создание контекста если его нет
                    if (SecurityContextHolder.getContext().getAuthentication() == null) {
                        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                    }
                //неправильная подпись, истек срок годности, нет username claim
                } catch (JWTVerificationException e) {
                    response.sendError(response.SC_BAD_REQUEST, "Invalid JWT");
                }
            }
        }
        filterChain.doFilter(request, response);
    }
}
