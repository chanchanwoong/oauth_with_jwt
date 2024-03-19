package com.chanwoong.oauthandjwt.service;

import com.chanwoong.oauthandjwt.dto.*;
import com.chanwoong.oauthandjwt.entity.UserEntity;
import com.chanwoong.oauthandjwt.repository.UserRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    // DB 접근을 위해 UserRepository 들고온다.
    private final UserRepository userRepository;
    public CustomOAuth2UserService(UserRepository userRepository){
        this.userRepository = userRepository;
    }

    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);
        System.out.println("oAuth2User >> " + oAuth2User);

        // naver에서 왔는지 구글에서 왔는지 확인
        String registrationId = userRequest.getClientRegistration().getRegistrationId();

        // 응답을 저장한 바구니 미리 초기화
        OAuth2Response oAuth2Response = null;

        // 각 제공 회사별 처리
        if (registrationId.equals("naver")) {
            oAuth2Response = new NaverResponse(oAuth2User.getAttributes());
        }
        else if (registrationId.equals("google")) {
            oAuth2Response = new GoogleResponse(oAuth2User.getAttributes());
        }
        else {
            return null;
        }



        // 로그인을 진행하는 과정
        // OAuth2User 라는 Dto(여기서는 CustomOAuth2User)에 담아서 OAuth2LoginAuthenticationProvider에 넘겨주는 과정

        // 리소스 서버에서 발급 받은 정보로 사용자를 특정할 아이디 값 생성
        String username = oAuth2Response.getProvider() + " " + oAuth2Response.getProviderId();



        // username을 통해 DB 접근해서 있는 유저인지 없는 유저인지 확인하는 과정
        UserEntity existData = userRepository.findByUsername(username);

        // 존재하지 않는 경우
        if (existData == null){
            UserEntity userEntity = new UserEntity();
            userEntity.setUsername(username);
            userEntity.setEmail(oAuth2Response.getEmail());
            userEntity.setName(oAuth2User.getName());
            userEntity.setRole("ROLE_USER");

            userRepository.save(userEntity);

            // 담아줄 바구니(dto) 생성
            UserDTO userDTO = new UserDTO();
            userDTO.setUsername(username);
            userDTO.setName(oAuth2Response.getName());
            userDTO.setRole("ROLE_USER");

            return new CustomOAuth2User(userDTO);
        }

        // 존재하는 경우, 업데이트하면 된다.
        else {
            existData.setEmail(oAuth2Response.getEmail());
            existData.setName(oAuth2User.getName());

            userRepository.save(existData);

            UserDTO userDTO = new UserDTO();
            userDTO.setUsername(existData.getUsername());
            userDTO.setName(oAuth2Response.getName());
            userDTO.setRole(existData.getRole());

            return new CustomOAuth2User(userDTO);
        }
    }
}
