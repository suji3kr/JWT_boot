### *SPRING_BOOT  SECURITY*

--------------------------------
<br>
<br>

<br>



### 🔒 Spring Security, JWT, OAuth2의 장단점 비교
Spring Security는 강력한 보안 프레임워크로, 인증과 인가를 처리하는 데 널리 사용됩니다. 
특히, JWT(JSON Web Token)와 OAuth2 같은 인증 방식과 함께 사용될 수 있습니다. 
각각의 장단점을 살펴보겠습니다.

<br>

### 1. Spring Security
✅ 장점
강력한 보안 기능: 인증(Authentication)과 인가(Authorization)를 쉽게 구현 가능
유연한 확장성: 다양한 인증 방식(JWT, OAuth2, 세션 기반 인증 등)과 쉽게 연동 가능
스프링 생태계와 통합: Spring Boot 및 기타 스프링 기술들과 원활한 연동
❌ 단점
설정이 복잡함: 세부적인 설정이 많아 학습 곡선이 가파를 수 있음
초기 설정 비용: 보안 정책을 세밀하게 조정하려면 많은 설정이 필요함
단독으로는 인증 방식이 아님: JWT, OAuth2 등의 인증 방식과 함께 사용해야 실질적인 인증이 가능함

<br>

### 2. JWT (JSON Web Token)

**✅ 장점**
세션을 유지할 필요 없음: Stateless 방식으로 서버 부담이 적음 (특히 확장성 높은 시스템에 유리)
빠른 인증 처리: 토큰 자체에 사용자 정보가 포함되어 있어 별도의 DB 조회 없이 인증 가능
다양한 플랫폼에서 사용 가능: REST API, 모바일, 마이크로서비스 등 다양한 환경에서 활용 가능

**❌ 단점**
토큰 탈취 위험: 토큰이 유출되면 해당 유저의 권한이 그대로 노출될 위험이 있음 (해결책: 토큰 만료 시간 짧게 설정 & Refresh Token 사용)
토큰 크기가 큼: JWT에는 클레임(Claim) 정보가 포함되므로, 일반적인 세션 기반 인증보다 데이터 전송량이 증가할 수 있음
강제 로그아웃 어려움: 기존 토큰을 서버에서 무효화할 수 없고, 클라이언트에서 직접 폐기해야 함 (일반적인 해결책: 블랙리스트 저장 또는 짧은 만료시간 설정)

### 3. OAuth2 (Open Authorization 2.0)
**✅ 장점**
소셜 로그인 지원: Google, Facebook, GitHub 같은 외부 서비스를 이용한 인증이 가능
보안성이 높음: 액세스 토큰과 리프레시 토큰을 활용하여 보안성을 강화할 수 있음
권한 위임 가능: 특정 권한만 부여하여 서비스 간의 안전한 데이터 공유가 가능

**❌ 단점**
구현이 복잡함: OAuth2의 흐름(Authorization Code, Implicit, Password Credentials, Client Credentials)이 복잡하여 설정이 어려움
액세스 토큰 관리 필요: 토큰의 유효기간을 관리해야 하고, 리프레시 토큰을 활용하여 갱신하는 추가적인 로직이 필요함
외부 서비스 의존성: 소셜 로그인(예: Google OAuth)을 사용할 경우, 해당 서비스의 정책 변경에 영향을 받을 수 있음

✅ 언제 어떤 방식을 사용해야 할까?
비교 항목	JWT	OAuth2
주요 사용 사례	REST API 인증, 마이크로서비스	소셜 로그인, 서드파티 서비스 연동
보안 수준	중간 (토큰 유출 시 위험)	높음 (권한 위임 및 갱신 가능)
서버 부담	낮음 (Stateless)	중간 (토큰 갱신 및 외부 서비스 연동 필요)
구현 난이도	쉬움 (토큰 생성 및 검증)	어려움 (OAuth 흐름 구현 필요)

**📌 결론**
JWT: 단순한 REST API 인증이 필요하고, Stateless한 시스템이 필요할 때 유용
OAuth2: 소셜 로그인, 서드파티 API 연동, 권한 위임이 필요한 경우 적합
Spring Security: 보안 정책을 더욱 강화하고 싶을 때 필수적으로 사용
만약 내부 서비스(API 서버) 간 인증이 필요하다면 JWT가 적합하고,
**사용자 기반의 OAuth 인증(소셜 로그인 등)**이 필요하다면 OAuth2를 고려하는 것이 좋습니다.
😊


<br><br>



------------------------------------
<br><br>

![image](https://github.com/user-attachments/assets/a9efa567-f789-4046-b586-bf8084977db5)

<br>

          package com.company.cardatabase.config;
          
          import org.springframework.context.annotation.Bean;
          import org.springframework.context.annotation.Configuration;
          import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
          import org.springframework.security.core.userdetails.User;
          import org.springframework.security.core.userdetails.UserDetails;
          import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
          import org.springframework.security.crypto.password.PasswordEncoder;
          import org.springframework.security.provisioning.InMemoryUserDetailsManager;
          
          @Configuration
          @EnableWebSecurity
          public class SecurityConfig {
          
          
              @Bean
              public InMemoryUserDetailsManager userDetailsService(){
                  UserDetails user = User.builder().username("user")
                          .password(passwordEncoder().encode("password"))
                          .roles("USER")
                          .build();
          
                  return new InMemoryUserDetailsManager(user);
          
              }
              @Bean
              public PasswordEncoder passwordEncoder(){
                  return new BCryptPasswordEncoder();
              }
          }


<br>
<br>
CardatabaseApplication
<br>


              // 사용자명 : user, 비밀번호 : user
              urepository.save(new AppUser("user",
                    "$2a$10$NVM0n8ElaRgg7zWO1CxUdei7vWoPg91Lz2aYavh9.f9qe4bRadue", "USER"));
          
              // 사용자명 : admin, 비밀번호 : admin
              urepository.save(new AppUser("admin",
                    "$2a$10$8cjz47bjbR4Mn8GMg9IZx.vyjhLXR/SKKMSZ9.mP9vpMu0ssKi8GW", "ADMIN"));
          
          }


<br>

<br>

          @RepositoryRestResource(exported =false)
          public interface AppUserRepository extends CrudRepository<AppUser, Long> {
              Optional<AppUser> findByUsername(String username);
          }

<br>


![image](https://github.com/user-attachments/assets/509bb1f7-4300-44a5-bfa9-48f003a4cec4)

<br>

### @RepositoryRestResource(exported =false)//주석처리하면...?
#### 사용자 정보가 드러나게됨..!

admin 로그인 후 정부를 볼 때user 의 정보가 보이지 않게 하기 위해 
@RepositoryRestResource(exported =false)
false로 지정해야 보이지 않는다.

<br>

![image](https://github.com/user-attachments/assets/46911832-a565-4d6b-a121-a559734a5e91)

<br>
<br>


### JWT 으로 백앤드 보호하기 
      https://jwt.io/
      패스워드

          implementation 'io.jsonwebtoken:jjwt-api:0.11.5'
          runtimeOnly 'io.jsonwebtoken:jjwt-impl:0.11.5', 'io.jsonwebtoken:jjwt-jackson:0.11.5'


<br>

![image](https://github.com/user-attachments/assets/e1c6ecde-b48e-4b6e-9bd8-431a876d35c6)



<br><br>


![image](https://github.com/user-attachments/assets/0ea768a6-3538-443d-97df-8cf75f74fda0)

<br><br>

                    package com.company.cardatabase.service;
                    
                    import org.springframework.stereotype.Component;
                    
                    @Component  // 서비스와 다른 의미의 토큰으로 쓰려고 컴포넌트를 씀, 자체 저장.. 사실 service쓸수도 있지만 class집어넣을땐 component
                    public class JwtService {
                        //1일
                        static final long EXPIRATIONTIME = 86400000;
                        static final String PREFIX = "Bearer";
                    
                        //비밀키 생성, 시연 목적으로만 이용
                        static final Key key =Keys.secretKeyFor(SignatureAlgorithm.ES256);
                        // 운영 환경에선 애플리케이션 구성에서 읽어들여와야함
                    
                    
                        //서명된 JWT 토큰을 생성
                        public String getToken(String username){
                            String token = Jwts.builder()
                                    .setSubject(username)
                                    .setExpiration(new Date(System.currentTimeMillis()+
                                            EXPIRATIONTIME))
                                    .signWith(key)
                                    .compact();
                            return token;
                        }


<br><br>

-----------------------------------------------------------

<br>

시간 끝 
.setExpiration

                    
                    
                        //요청의 Authorization 헤더에서 토큰을 가져온뒤
                        //토큰을 확인하고 사용자 이름을 가져옴
                        public  String getAuthUser(HttpServletRequest request){
                            String token =request.getHeader
                                    (HttpHeaders.AUTHORIZATION);
                            if (token != null){
                                String user = Jwts.parserBuilder()
                                        .setSigningKey(key)
                                        .build()
                                        .parseClaimsJws(token.replace(PREFIX, ""))
                                        .getBody()
                                        .getSubject();
                                if (user!= null)
                                    return user;
                            }
                            return  null;
                        }
                    }


<br>



                    
                    import com.company.cardatabase.service.JwtService;
                    import lombok.RequiredArgsConstructor;
                    import org.springframework.http.HttpHeaders;
                    import org.springframework.http.ResponseEntity;
                    import org.springframework.security.authentication.AuthenticationManager;
                    import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
                    import org.springframework.security.core.Authentication;
                    import org.springframework.web.bind.annotation.PostMapping;
                    import org.springframework.web.bind.annotation.RequestBody;
                    import org.springframework.web.bind.annotation.RestController;
                    
                    @RestController
                    @RequiredArgsConstructor
                    public class LoginController {
                        private final JwtService jwtService;
                        private final AuthenticationManager authenticationManager;
                    
                    
                        @PostMapping("/login")
                        public ResponseEntity<?> getToken(@RequestBody
                                                              AccountCredentials credentials){
                            //토큰을 생성하고 응답의 Authorization 헤더로 전송
                            UsernamePasswordAuthenticationToken creds = new
                                    UsernamePasswordAuthenticationToken(credentials.username(),
                                    credentials.password());
                            Authentication auth = authenticationManager.authenticate(creds);
                    
                            //토큰을 생성
                            String jwts = jwtService.getToken(auth.getName());
                    
                            //생성된 토큰으로 응답을 빌드
                            return ResponseEntity.ok().header(HttpHeaders.AUTHORIZATION,
                                    "Bearer" + jwts).header(HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS,
                                    "Authorization").build();
                        }
                    }
                    
                    
                    
                        @Bean
                        public AuthenticationManager authenticationManager(
                                AuthenticationConfiguration authConfig) throws Exception{
                            return authConfig.getAuthenticationManager();
                        }
                    }
                    



<br><br>




![image](https://github.com/user-attachments/assets/2b281558-7fe3-4490-bf59-1c2853f4997c)

<br>

          @Bean
          public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
              http.csrf((csrf)-> csrf.disable())
                      .sessionManagement((sessionManagement)-> sessionManagement
                              .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                      .authorizeHttpRequests((authorizeHttpRequests)->
                              authorizeHttpRequests.requestMatchers(HttpMethod.POST,
                                      "/login").permitAll().anyRequest().authenticated());
              return http.build();
          }

<br>



<br>

<br>

![image](https://github.com/user-attachments/assets/c23d1634-a1b2-4424-926b-d6f9899fb217)

<br><br>


<br>

![image](https://github.com/user-attachments/assets/3797c2e4-a09e-47d6-92fb-5a58f5ce2343)


<br><br>

![image](https://github.com/user-attachments/assets/28e9c6b1-66e1-4a3b-ba1b-67becedb3f06)



<br>
<br>

![image](https://github.com/user-attachments/assets/07a6eb54-c796-438d-83c2-9c7ca87bf536)


<br>
<br>


![image](https://github.com/user-attachments/assets/eec7c1ac-ab2d-4ce7-980b-9b330d82c30e)

<br>

<br>



