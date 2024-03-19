package com.chanwoong.oauthandjwt.jwt;

import com.chanwoong.oauthandjwt.config.SecurityConfig;
import com.chanwoong.oauthandjwt.dto.CustomOAuth2User;
import com.chanwoong.oauthandjwt.dto.UserDTO;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class JWTFilter extends OncePerRequestFilter {

    // JWT 검증을 위해 사용
    private final JWTUtil jwtUtil;
    public JWTFilter(JWTUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // 쿠키들을 다 부르고 Authrization key에 담긴 쿠키를 찾는다.
        String authorization = null;
        Cookie[] cookies = request.getCookies();
        for (Cookie cookie : cookies){
            System.out.println("쿠키 이름 > " + cookie.getAttributes());
            if (cookie.getName().equals("Authorization")){
                authorization = cookie.getValue();
            }
        }
        // Authorization 헤더 검증
        if (authorization == null){
            System.out.println("token null");
            filterChain.doFilter(request, response);

            return;
        }

        String token = authorization;

        // 토큰 소멸 검증
        if(jwtUtil.isExpired(token)){
            System.out.println("token expired");
            filterChain.doFilter(request, response);

            return;
        }

        // 토큰에서 username과 role 추출
        String username = jwtUtil.getUsername(token);
        String role = jwtUtil.getRole(token);

        // userDTO 생성해서 값 set
        UserDTO userDTO = new UserDTO();
        userDTO.setUsername(username);
        userDTO.setRole(role);

        // UserDetails 바구니에 회원 정보 객체 담기
        CustomOAuth2User customOAuth2User = new CustomOAuth2User(userDTO);

        // 스프링 시큐리티 인증 토큰 생성
        Authentication authToken = new UsernamePasswordAuthenticationToken(customOAuth2User, null, customOAuth2User.getAuthorities());

        // 세션에 사용자 등록
        SecurityContextHolder.getContext().setAuthentication(authToken);

        filterChain.doFilter(request, response);



        // SecurityConfig에 등록해야 한다.
    }
}
