# 스프링 시큐리티 6.x

## 초기화 과정 이해
### 자동 설정의 의한 기본 보안 작동
* 서버가 기동되면 스프링 시큐리티의 초기화 작업 및 보안 설정이 이루어진다.
* 별도의 설정이나 코드를 작성하지 앟ㄴ아도 기본적인 웹 보안 기능이 현재 시스템에 연동되어 작동한다.
  * 기본적인 모든 요청에 대하여 인증여부를 검증하고 인증이 승인되어야 작원에 접근이 가능하다.
  * 인증 방식은 폼 로그인 방식과 httpBasic 로그인 방식으로 제공한다.
  * 인증을 시도할 수 있는 로그인 페이지가 자동적으로 생성되어 렌더링 된다.
  * 인증 승인이 이루어질 수 있도록 한 개의 계정이 기본적으로 제공된다.
    * SecurityProperties 설정 클래스에서 생성
    * username: user
    * password: 랜덤 문자열

### SecurityBuilder / SecurityConfigurer
* 개념
  * SecurityBuilder는 빌더 클래스로서 웹 보안을 구성하는 빈 객체와 설정 클래스들을 생성하는 역할을 하며 대표적으로 WebSecurity, HttpSecurity가 있다.
  * SecurityConfigurer는 Http 요청과 관련된 보안처리를 담당하는 필터들을 생성하고 여러 초기화 설정에 관여한다.
  * SecurityBuilder는 SecurityConfigurer를 참조하고 있으며 인증 및 인가 초기화 작업은 SecurityConfigurer에 의해 진행된다.

### WebSecurity / HttpSecurity
#### HttpSecurty
* HttpSecurityConfiguration에서 HttpSecurity를 생성하고 초기화 한다.
* HttpSecurity는 보안에 필요한 각 설정 클래스와 필터들을 생성하고 최종적으로 `SecurityFilterChain` 빈 생성

> SecurityFilterChain
* boolean matches(HttpServletRequest request)
  * 이 메서드는 요청이 현재 SecurityFilterChain에 의해 처리되어야 하는지 여부를 결정한다.
  * true를 반환하면 현재 요청이 이 필터 체인에 의해 처리되어야 함을 의미하면, false를 반환하면 다른 필터 체인이나 로직에 의해 처리되어야 함을 의미한다.
  * 이를 통해 특정 요청에 대해 적절한 보안 필터링 로직이 적용될 수 있도록 한다.
* List<Filter> getFilters()
  * 이 메서드는 현재 SecurityFilterChain에 포함된 Filter 객체의 리스트를 반환한다.
  * 이 메서드를 통해 어떤 필터들이 현재 필터 체인에 포함되어있는지 확인할 수 있으며, 각 필터는 요청 처리 과정에서 특정 작업(예: 인증, 권한 부여, 로깅 등)을 수행한다.

#### WebSecurity
* WebSecurityConfiguration에서 WebSecurity를 생성하고 초기화를 진행한다.
* WebSecurity는 HttpSecurity에서 생성한 SecurityFilterChain 빈을 SecurityBuilder에 저장한다.
* WebSecurity가 build()를 실행하면 SecurityBuilder에서 SecurityFilterChain을 꺼내어 FilterChainProxy 생성자에게 전달 한다.

### DelegatingFilterProxy / FilterChainProxy
* Filter
  * 서블릿 필터는 웹 애플리케이션에서 클라이언트의 요청과 서버의 응답을 가공하거나 검사하는데 사용되는 구성 요소이다.
  * 서블릿 필터는 클라이언트의 요청이 서블릿에 도달하기 전이나 서블릿이 응답을 클라이언트에게 보내기 전에 특정 작업을 수행할 수 있다.
  * 서블릿 필터는 서블릿 컨테이너(WAS)에서 생성되고 실행되고 종료된다.

* DelegatingFilter
  * DelegatingFilterProxy는 스프링에서 사용되는 특별한 서블릿 필터로, 서블릿 컨테이너와 스프링 애플리케이션 컨텍스트 간의 연결고리 역할을 하는 필터이다.
  * DelegatingFilterProxy는 서블릿 필터의 기능을 수행하는 동시에 스프링의 의존성 주입 및 빈 관리 기능과 연동되도록 설계된 필터라 할 수 있다.
  * DelegatingFilterProxy는 "springSecurityFilterChain" 이름으로 생성된 빈을 ApplicationContext에서 찾아 요청을 위임한다.
  
* FilterChainProxy
  * springSecurityFilterChain의 이름으로 생성되는 필터 빈으로서 DelegatingFilterProxy로부터 요청을 위임 받고 보안 처리 역할을 한다.
  * 내부적으로 하나 이상의 SecurityFilterChain 객체들을 가지고 있으며 요청 URL 정보를 기준으로 적절한 SecurityFilterChain을 선택하여 필터들을 호출한다.
  * HttpSecurity를 통해 API 추가 시 관련 필터들이 추가 된다.
  * 사용자의 요청을 필터 순서대로 호출함으로 보안 기능을 동작시키고 필요 시 직접 필터를 생성해서 기존의 필터 전, 후로 추가 가능하다.

### 사용자 정의 보안 기능 구현
* 한 개 이상의 SecurityFilterChain 타입의 빙을 정의한 후 인증 API 및 인가 API를 설정한다.
1. SecurityConfig 클래스 생성 및 `@EnableWebSecurity` 애노테이션 선언.
2. SecurityFilterChain 빈으로 정의
3. HttpSecurity 빈을 DI 받는다.

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequest(auth -> auth.anyRequest().authenticated())
            .formLogin(Customizer.withDefaults());
    return http.build();
  }
}
```
* `@EnableWebSecurity` 애노테이션을 선언한다.
* 모든 설정 코드는 람다 형식으로 작성해야 한다(스프링 시큐리티 7버전 부터는 람다 형식만 지원 할 예정)
* SecurityFilterChain을 빈으로 정의하게 되면 자동설정에 의한 SecurityFilterChain 빈은 생성되지 않는다.

### 사용자 추가 설정
* application.properties 혹은 application.yml 파일에 설정한다.
```yml
Spring:
  security:
    user:
      name: user
      password: 1111
      role: USER
```
* 자바 설정 클래스에 직접 정의 한다.

```java
import java.beans.BeanProperty;

@Bean
public InMemoryUserDetailsManager inMemoryUserDetailsManager() {
    UserDetails user = User.withUsername("user")
            .password("{noop}1111")
            .authorities("USER")
            .build();
    return new InMemoryUserDetailsManager(user);
}
```

---

## 인증 프로세스
### 폼 인증 - formLogin()
* 폼 인증
  * HTTP 기반의 폼 로그인 인증 메커니즘을 활성화하는 API로서 사용자 인증을 위한 사용자 정의 로그인 페이지를 쉽게 구현할 수 있다.
  * 기본적으로 스프링 시큐리티가 제공하는 기본 로그인 페이지를 사용하며 사용자 이름과 비밀번호 필드가 포함된 간단한 로그인 양식을 제공한다.
  * 사용자는 웹 폼을 통해 자격증명(사용자 이름과 비밀번호)을 제공하고 Spring Security는 HttpServletRequest에서 이 값을 읽어 온다.

* formLogin() API
  * FormLoginConfigurer 설정 클래스를 통해 여러 API들을 설정할 수 있다.
  * 내부적으로 UsernamePasswordAuthenticationFilter가 생성되어 폼 방식의 인증 처리를 담당하게 된다.

```java
HttpSecurity.formLogin(httpSecurityFormLoginConfigurer -> httpSecurityFormLoginConfigurer
        .loginPage("/loginPage")                        // 사용자 정의 로그인 페이지로 전환, 기본 로그인 페이지 무시
        .loginProcessingUrl("/loginProc")               // 사용자 이름과 비밀번호를 검증할 URL 지정 (form action)
        .defaultSuccessUrl("/", [alwaysUse])            // 로그인 성공 이후 이동 페이지, alwaysUse가 true이면 무조건 지정된 위치로 이동 (기본값 false)
                                                        // 인증 전에 보안이 필요한 페이지를 방문하다 인증에 성공한 경유이면 이전 위치로 리다이렉트 됨
        .failureUrl("/failed")                          // 인증에 실패할 경우 사용자에게 보내질 URL을 지정, 기본 값은 "/login?error"이다.
        .usernameParameter("username")                  // 인증을 수행할 때 사용자 이름(아이디)를 찾기 위해 확인하는 HTTP 매개변수 설정, 기본값은 username
        .userPasswordParameter("password")              // 인증을 수행할 때 비밀번호를 찾기 위해 확인하는 HTTP 매개변수 설정, 기본값은 password
        .failureHandler(AuthenticationFailHandler)      // 인증 실패시 사용할 AuthenticationFailureHandler를 지정
                                                        // 기본값은 SimpleUrlAuthenticationFailureHandler를 사용하여 "/login?error"로 리다이렉트 함
        .successHandler(AuthenticationSuccessHandler)   // 인증 성공할 시 사용할 AuthenticationSuccessHandler를 지정
                                                        // 기본값은 SavedRequestAwareAuthenticationSuccessHandler이다.
        .permitAll()                                    // failureUrl(), loginPage(), loginProcessingUrl()에 대한 URL에 모든 사용자의 접근을 허용함.
);
```

### 폼 인증 필터 - UsernamePasswordAuthenticationFilter
* UsernamePasswordAuthenticationFilter
  * 스프링 시큐리티는 AbstractAuthenticationProcessingFilter 클래스를 사용자의 자격 증명을 인증하는 기본 필터로 사용한다.
  * UsernamePasswordAuthenticationFilter는 AbstractAuthenticationProcessingFilter를 확장한 클래스로서 HttpServletRequest에서 제출된 사용자 이름과 비밀번호로부터 인증을 수행한다.
  * 인증 프로세스가 초기화 될 때 로그인 페이지와 로그아웃 페이지 생성을 위한 DefaultLoginPageGeneratingFilter 및 DefaultLogoutPageGeneratingFilter가 초기화 된다.

### 기본 인증 - httpBasic()
* HTTP는 액세스 제어와 인증을 위한 프레임워크를 제공하며 가장 일반적인 인증방식은 'Basic' 인증 방식이다.
* RFC7235 표준이며 인증 프로토콜은 HTTP 인증 헤더에 기술 되어있다.

1. 클라이언트는 인증정보 없이 서버로 접속을 시도한다.
2. 서버가 클라이언트에게 인증요구를 보낼 때 401 Unauthorized 응답과 함께 WWW-Authenticate 헤더를 기술해 realm(보안영역)과 Basic 인증방법을 보냄
3. 클라이언트가 서버로 접속할 때 Base64로 username과 password를 인코딩하고 Authorization 헤더에 담아서 요청함
4. 성공적으로 완료되면 정상적인 상태 코드를 반환한다.

> 주의사항
* base-64 인코딩된 값은 디코딩이 가능하기 때문에 인증정보가 노출된다.
* HTTP Basic 인증은 반드시 HTTPS와 같이 TLS 기술과 함께 사용해야 한다.


* httpBasic() API
  * HttpBasicConfigurer 설정 클래스를 통해 여러 API들을 설정할 수 있다.
  * 내부적으로 BasicAuthenticationFilter가 생성되어 기본 인증 방식의 인증 처리를 담당하게 된다.

```java
HttpSecurity.httpBasic(HttpSecurityHttpBasicConfigurer -> httpSecurityHttpBasicConfigurer
        .realmName("security")                              // HTTP 기본 영역을 설정한다.
        .authenticationEntryPoint(
                (request, response, authException) -> {})   // 인증 실패 시 호출되는 AuthenticationEntryPoint 이다.
                                                            // 기본값은 "Realm" 영역으로 BasicAuthenticationEntryPoint가 사용된다.
);
```

### BasicAuthenticationFilter
* BasicAuthenticationFilter
  * 이 필터는 기본 인증 서비스를 제공하는 데 사용된다.
  * BasicAuthenticationConverter를 사용해서 요청 헤더에 기술된 인증정보의 유효성을 체크하며 Base64 인코딩된 username과 password를 추출한다.
  * 인증 이후 세션을 사용하는 경우와 사용하지 않는 경우에 따라 처리되는 흐름에 차이가 있다. 세션을 사용하는 경우 매 요청 마다 인증과정을 거치지 않으나 세션을 사용하지 않는 경우 매 요청마다 인증과정을 거쳐야 한다.

### RememberMe 인증
* RememberMe
  * 사용자가 웹 사이트나 애플리케이션에 로그인할 때 자동으로 로그인 정보를 기억하는 기능이다.
  * UsernamePasswordAuthenticationFilter와 함께 사용되며, AbstractAuthenticationProcessingFilter 슈퍼클레스에서 훅을 통해 구현된다.
    * 인증 성공 시 RememberMeService.loginSuccess()를 통해 RememberMe 토큰을 생성하고 쿠키로 전달 한다.
    * 인증 실패 시 RememberMeService.logingFail()를 통해 쿠키를 지운다.
    * LogoutFilter와 연계해서 로그아웃 시 쿠키를 지운다.

* 토큰 생성
  * 기본적으로 암호화된 토큰으로 생성 되어지며 브라우저에 쿠키를 보내고, 향후 세션에 이 쿠키를 감지하여 자동 로그인이 이루어지는 방식으로 달성된다.
    * base64(username + ":" + expirationTime + ":" + algorithmName + ":" + algorithmHex(username + ":" + expirationTime + ":" + password + ":" + key))
      * username: UserDetailsService로 식별 가능한 사용자 이름
      * password: 검색된 UserDetails에 일치하는 비밀번호
      * expirationTime: remember-me 토큰이 만료되는 날짜와 시간, 밀리초로 표현
      * key: remember-me 토큰의 수정을 방지하기 위한 개인키
      * algorithmName: remember-me 토큰 서명을 생성하고 검증하는 데 사용되는 알고리즘(기본적으로 SHA-256 알고리즘을 사용)

* RememberMeService 구현체
  * TokenBasedRememberMeServices - 쿠키 기반 토큰의 보안을 위해 해싱을 사용한다.
  * PersistentTokenBasedRememberMeServices - 생성된 토큰을 저장하기 위해 데이터베이스나 다른 영구 저장 매체를 사용한다.
  * 두 구현 모두 사용자의 정보를 검색하기 위한 UserDetailsService가 필요하다.

* rememberMe() API
  * RememberMeConfigurer 설정 클래스를 통해 여러 API를 설정할 수 있다.
  * 내부적으로 RememberMeAuthenticationFilter가 생성되어 자동 인증 처리를 담당하게 된다.

```java
http.rememberMe(httpSecurityRmemeberMeConfigurer -> httpSecurityRememberMeConfigurer
        .alwaysRemember(true)                   // "기억하기(remember-me)" 매개변수가 설정되지 않을 때에도 쿠키가 항상 생성되어야 하는지에 대한 여부를 나타낸다.
        .tokenValiditySeconds(3600)             // 토큰이 유효한 시간(초 단위)을 지정할 수 있다.
        .userDetailService(userDetailService)   // UserDetails를 조회하기 위해 사용되는 UserDetailsService를 지정한다.
        .rememberMeParameter("remember")        // 로그인 시 사용자를 기억하기 위해 사용되는 HTTP 매개변수이며 기본값은 'remember-me'이다.
        .rememberMeCookieName("remember")       // 기억하기(remember-me) 인증을 위한 토큰을 저장하는 쿠키 이름이며 기본 값은 'remember-me'이다.
        .key("security")                        // 기억하기(remember-me) 인증을 위해 생성된 토큰을 식별하는 키를 설정한다.
);
```

### RememberMeAuthenticationFilter
* RememberMeAuthenticationFilter
  * securityContextHolder에 Authentication이 포함되지 않은 경우 실행되는 필터이다.
  * 세션이 만료되었거나 애플리케이션 종료로 인해 인증 상태가 소멸된 경우 토큰 기반 인증을 사용해 유효성을 검사하고 토큰이 검증되면 자동 로그인 처리를 수행한다.

### 익명 사용자 - Anonymous
* 익명 사용자
  * 스프링 시큐리티에서 '익명으로 인증된' 사용자와 인증되지 않은 사용자 간에 실제 개념적 차이는 없으며 단지 액세스 제어 속성을 구성하는 더 편리한 방법을 제공한다고 볼 수 있다.
  * SecurityContextHolder가 항상 Authentication 객체를 포함하고 null을 포함하지 않는다는 규칙을 세우게 되면 클래스를 더 견고하게 작성할 수 있다.
  * 인증 사용자와 익명 인증 사용자를 구분해서 어떤 기능을 수행하고자 할 때 유용할 수 있으며 익명 인증 객체를 세션에 저장하지 않는다.
  * 익명 인증 사용자의 권한을 별도로 운용할 수 있다. 즉 인증된 사용자가 접근할 수 없더록 수성이 가능하다.

```java
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
      .formLogin(Customizer.withDefaults())
      .anonymous(anonymous -> anonymous.principal("guest").authorities("GUEST")
    );
}
```

#### 스프링 MVC에서 익명 인증 사용하기
* 스프링 MVC가 HttpServletRequest#getPrincipal을 사용하여 파라미터를 해결하는데 요청이 익명일 때 이 값은 null 이다
```java
public String method(Authentication authentication) {
    if (authentication instanceof AnonymousAuthenticationToken) {
        return "anonymous";
    } else {
        return "not anonymous";
    }
}
```

* 익명 요청에서 Authentication을 얻고 싶다면 @CurrentSecurityContext를 사용하면 된다.
* CurrentSecurityContextArgumentResolver에서 요청을 가로채어 처리한다
```java
public String method(@CurrentSecurityContext SecurityContext context) {
    return context.getAuthentication().getName();
}
```

#### AnonymousAuthenticationFilter
* SecurityContextHolder에서 Authentication 객체가 없을 경우 감지하고 필요한 경우 새로운 Authentication 객체로 채운다.

### 로그아웃 - logout
* logout
  * 스프링 시큐리티는 기본적으로 DefaultLogoutPageGeneratingFilter를 통해 로그아웃 페이지를 제공하며 "GET/logout" URL로 접근이 가능하다.
  * 로그아웃 실행은 기본적으로 "POST/logout"으로만 가능하나 CSRF 기능을 비활성화 할 경우 혹은 RequestMatcher를 사용할 경우 GET, PUT, DELETE 모두 가능하다.
  * 로그아웃 필터를 거치지 않고 스프링 MVC에 커스텀하게 구현할 수 있으며 로그인 페이지가 커스텀하게 생성될 경우 로그아웃 기능도 커스텀하게 구현해야 한다.

* logout() API
```java
http.logout(httpSecurityLogoutConfigurer -> httpSecurityLogoutConfigurer
        .logoutUrl("/logoutProc")   // 로그아웃이 발생하는 URL을 지정한다 (기본값은 "/logout" 이다)
        .logoutRequestMatcher(new AntPathRequestMatcher("/logoutProc", "POST")) // 로그아웃이 발생하는 RequestMatcher를 지정한다. logoutUrl보다 우선적이다.
                                                                                // Method를 지정하지 않으면 logout URL이 어떤 HTTP 메서드로든 요청될 때 로그아웃 할 수 있다.
        .logoutSuccessUrl("/logoutSuccess")     // 로그아웃이 발생한 후 리다이렉션 될 URL이다. 기본값은 "login?logout"이다.
        .logoutSuccessHandler((request, response, authentication) -> {  // 사용할 LogoutSuccessHandler를 설정한다. 
            response.sendRedirect("/logoutSuccess")                     // 이것이 지정되면 logoutSuccessUrl(String)은 무시된다.
        })
        .deleteCookies("JSESSIONID", "CUSTOM_COOKIE")   // 로그아웃 성공시 제거될 쿠키의 이름을 지정할 수 있다.
        .invalidateHttpSession(true) // HttpSession을 무효화해야 하는 경우 true(기본값), 그렇지 않으면 false
        .clearAuthentication(true) // 로그아웃시 SecurityContextLogoutHandler가 인증(Authentication)을 삭제해야 하는지 여부를 명시한다.
        .addLogoutHandler((request, response, authentication) -> {}) // 기존 로그아웃 핸들러 뒤에 새로운 LogoutHandler를 추가한다.
        .permitAll() // loutoutUrl(), RequestMatcher()의 URL에 대한 모든 사용자의 접근을 허용함.
)
```

### RequestCache / SavedRequest
* RequestCache
  * 인증 절차 문제로 리다이렉트 된 후에 이전에 했던 요청 정보를 담고 있는 'SavedRequest' 객체를 쿠키 혹은 세션에 저장하고 필요시 다시 가져와 실행하는 캐시 메커니즘이다.

* SavedRequest
  * SavedRequest는 로그인과 같은 인증 절차 후 사용자를 인증 이전의 원래 페이지로 안내하여 이전 요청과 관련된 여러 정보를 저장한다.

* reqeustCache() API
  * 요청 Url에 customParam=y라는 이름의 매개변수가 있는 경우에만 HttpSession에 저장된 SavedRequest을 꺼내오도록 설정할 수 있다(기본값은 "continue")
```java
HttpSessionRequestCache requestCache = new HttpRequestCache();
requestCahce.setMatchingReqeustParam("customParam=y");
http.reqeustCahce((cache) -> cache.requestCache(requestCache));
```

  * 요청을 지정하지 않도록 하려면 NullRequestCache 구현을 사용할 수 있다.
```java
HttpSessionRequestCache nullRequestCache = new NullRequestCache();
http.reqeustCahce((cache) -> cache.requestCache(nullRequestCache));
```

### RequestCacheAwareFilter
* ReqeustCacheAwareFilter는 이전에 저장했던 웹 요청을 다시 불러오는 역할을 한다.
* SavedRequest가 현재 Request와 일치하면 이 요청을 필터 체인의 doFilter 메소드에 전달하고 SavedRequest가 없으면 필터는 원래 Request를 그대로 진행시킨다.

---
## 인증 아키텍처
### Authentication
* 인증은 특정 자원에 접근하려는 사람의 신원을 확인하는 방법을 의미한다.
* 사용자 인증의 일반적인 방법은 사용자 이름과 비밀번호를 입력하게 하는 것으로서 인증이 수행되면 신원을 알고 권한 부여를 할 수 있다.
* Authentication은 사용자의 인증 정보를 저장하는 토큰 개념의 객체로 활용되며 인증 이후 SecurityContext에 저장되어 전역적으로 참조가 가능하다.

#### 구조
```java
public interface Principal { // 자바
    boolean implies(Subject);
    String getName();
    boolean equals(Object);
    int hasCode();
    String toString();
}
```

```java
public interface Authentication extends Principal, Serializable { // 스프링
  Collection<? extends GrantedAuthority> getAuthorities();
  Object getCredentials();
  Object getDetails();
  Object getPrincipal();
  boolean isAuthenticated();
  void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException;
}
```
* getAuthorities(): 인증 주체(principal)에게 부여된 권한을 나타낸다.
* getCredentials(): 인증 주체가 올바른 것을 증명하는 자격 증명으로서 대개 비밀번호를 의미한다.
* getDetails(): 인증 요청에 대한 추가적인 세부 사항을 저장한다. IP주소, 인증서 일련 번호 등이 될 수 있다.
* getPrincipal(): 인증 주체를 의미하며 인증 요청의 경우 사용자 이름을, 인증 후에는 UserDetails 타입의 객체가 될 수 있다.
* isAuthenticated(): 인증 상태를 반환 한다.
* setAuthenticated(): 인증 상태를 설정한다.

#### 인증 절차 흐름
1. 클라이언트가 로그인 요청 Get / login?username + password
2. AuthenticationFilter가 Authentication 객체 생성
   * 인증 처리 전 Authentication 객체를 생성(사용자가 입력한 username, password 설정)하고 AuthenticationManager에게 전달
3. Authentication 객체를 AuthenticationManager에게 전달
   * AuthenticationManager가 인증 처리 수행
   * 이 단계까지가 인증처리 전 단계
4. AuthenticationManager 인증처리 후 Authentication 객체를 생성하고 다시 AuthenticationFilter에게 전달
   * 객체는 인증된 정보를 기반으로 새로운 Authentication 생성한다. 
     * principal: 시스템에서 가지고 온 사용자 정보가 저장되며 주로 UserDetails 객체이다.
     * credentials: 주로 비밀번호이며 사용자가 인증된 후에 이 정보가 지워져 노출되지 않도록 한다.
     * authorities: 사용자에게 부여된 권한으로 GrantedAuthority 타입의 컬렉션을 제공한다.

### 인증 컨텍스트 - SecurityContext / SecurityContextHolder - 1
* SecurityContext
  * Authentication 저장: 현재 인증된 사용자의 Authentication 객체를 저장한다.
  * ThreadLocal 저장소 사용: SecurityContextHolder를 통해 접근되며 ThreadLocal 저장소를 사용해 각 스레드가 자신만의 보안 컨텍스트를 유지한다.
  * 애플리케이션 전반에 걸친 접근성: 애플리케이션의 어느 곳에서 접근 가능하며 현재 사용자의 인증 상태나 권한을 확인하는 데 사용된다.

* SecurityContextHolder
  * SecurityContext 저장: 현재 인증된 사용자의 Authentication 객체를 담고 있는 SecurityContext 객체를 저장한다.
  * 전략 패턴 사용: 다양한 저장 전략을 지원하기 위해 SecurityContextHolderStrategy 인터페이스를 사용한다.
  * 기본 전략: MODE_THREADLOCAL
  * 전락 모드 직접 지정: SecurityContextHolder.setStrategyName(String)

* SecurityContextHolder 저장 모드
  * MODE_THREADLOCAL: 기본 모드로, 각 스레드가 독립적인 보안 컨텍스트를 가집니다. 대부분의 서버 환경에 적합하다.
  * MODE_INHERITABLETHREDLOCAL: 부모 스레드로부터 자식 스레드로 보안 컨텍스트가 상속되며 작업을 스레드 간 분산 실행하는 경우 유용할 수 있다.
  * MODE_GLOBAL: 전역적으로 단일 보안 컨텍스트를 사용하며 서버 환경에서는 부적합하며 주로 간단한 애플리케이션에 적합하다.

#### 구조
```java

public interface SecurityContextHolderStrategy {
    void clearContext();

    SecurityContext getContext();

    default Supplier<SecurityContext> getDeferredContext() {
        return this::getContext;
    }

    void setContext(SecurityContext context);

    default void setDeferredContext(Supplier<SecurityContext> deferredContext) {
        this.setContext((SecurityContext)deferredContext.get());
    }

    SecurityContext createEmptyContext();
}

```
* clearContext(): 컨텍스트를 삭제한다.
* getContext(): 현재 컨텍스트를 얻는다.
* getDeferredContext(): 현재 컨텍스트를 반환하는 Supplier를 얻는다.
* setContext(): 현재 컨텍스트를 저장한다.
* setDeferredContext(): 현재 컨텍스트를 반환하는 Supplier를 저장한다.
* createEmptyContext(): 새롭고 비어있는 컨텍스트를 생성한다.

#### SecurityContext 참조 및 삭제
* SecurityContext 참조 - SecurityContextHolder.getContextHolderStrategy().getContext();
* SecurityContext 삭제 - SecurityContextHolder.getContextHolderStrategy().clearContext();

#### SecurityContextHolder & SecurityContext 구조
* 스레드 마다 할당 되는 전용 저장소에 SecurityContext를 저장하기 때문에 동시성의 문제가 없다.
* 스레드 풀에서 운용되는 스레드일 경우 새로운 요청이더라도 기존의 ThreadLocal이 재사용될 수 있기 때문에 클라이언트로 응답 직전에 SecurityContext를 삭제해 주고 있다.

#### SecurityContextHolderStrategy 사용하기
* 기본 방식 
```java
SecurityContext context = SecurityContextHolder.createEmptyContext();
context.setAuthentication(authentication);
SecurityContextHolder.setContext(context);
```
위 코드는 SecurityContextHolder를 통해 SecurityContext에 정적으로 접근할 때 여러 애플리케이션 컨텍스트가 SecurityContextHolderStrategy를 지정하려고 할 때 경쟁 조건을 만들 수 있다.

```java
SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();
SecurityContext context = securityContextHolderStrategy.createEmptyContext();
context.setAuthentication(authentication);
securityContextHolderStrategy.setContext(context);
```
애플리케이션이 SecurityContext를 정적으로 접근하는 대신 SecurityContextHolderStrategy를 자동으로 주입이 될 수 있도록 한다.
각 애플리케이션 컨텍스트는 자신에게 가장 적합한 보안 전략을 사용할 수 있게 된다.

### 인증 관리자 - AuthenticationManager
* AuthenticationManager
  * 인증 필터로부터 Authentication 객체를 전달 받아 인증을 시도하며, 성공할 경우 사용자 정보, 권한 등을 포함한 완전히 채워진 Authentication 객체를 반환한다.
  * AuthenticationManager는 여러 AuthenticationProvider들을 관리하며 AuthenticationProvider 목록을 순차적으로 순회하며 인증 요청을 처리한다.
  * AuthenticationProvider 목록 중에서 인증 처리 요건에 맞는 적절한 AuthenticationProvider를 찾아 인증처리를 위임한다.
  * AuthenticationManagerBuilder에 의해 객체가 생성되며 주로 사용하는 구현체로 ProviderManager가 제공된다.

* AuthenticationManagerBuilder
  * AuthenticationManager 객체를 생성하며 UserDetailService 및 AuthenticationProvider를 추가할 수 있다.
  * HttpSecurity.getSharedObject(AuthenticationManagerBuilder.class)를 통해 객체를 참조할 수 있다.

#### AuthenticationManager 흐름도
1. AuthenticationFilter라 사용자 입력정보를 기반으로 Authentication 객체를 만들어 AuthenticationManager에게 인증 위임
2. AuthenticationManager는 사용자가 시도한 인증방법에 알 맞은 AuthenticationProvider를 찾아서 인증 위임
3. AuthenticationProvider는 인증후 새로운 Authentication 객체를 생성해 AuthenticationManager에게 반환
4. AuthenticationManager는 반환 받은 Authentication 객체를 AuthenticationFilter에게 반환

* 선택적으로 부모 AuthenticationManager를 구성할 수 있으며 이 부모는 AuthenticationProvider가 인증을 수행할 수 없는 경우(OAuth2)에 추가적으로 탐색할 수 있다.
* 일반적으로 AuthenticationProvider로부터 null이 아닌 응답을 받을 때까지 차례대로 시도하며 응답을 받지 못하면 ProviderNotFoundException과 함께 인증이 실패한다.

#### AuthenticationManager 사용 방법 - HttpSecurity 사용

```java
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
    AuthenticationManager authenticationManager = authenticationManagerBuilder.build();      // build()는 최초 한번 만 호출 해야 한다.
    authenticationManager authenticationManager = authenticationManagerBuilder.getObject();  // build()후에는 getObject()로 참조해야 한다.
  
  
  http.authorizeHttpRequest(auth -> auth
          .requestMatcher("/api/loing").permitAll()
          .anyRequest().authenticated())
      .authenticationManager(authenticationManager)  // HttpSecurity에서 생성한 AuthentiactionManager를 저장한다.
      .addFilterBefore(customFilter(http, authenticationManager), UsernamePasswordAuthenticationFilter.class);
  
  return http.build();
}

//@Bean으로 선언하면 안된다. AuthenticationManager는 빈이 아니기 때문에 주입받지 못한다.
public CustomAuthenticationFilter customFilter(HttpSecurity http, AuthenticationManager authenticationManager) throws Exception {
    CustomAUthenticationFilter customAUthenticationFilter = new CustomAuthenticationFilter(http);
    customAUthenticationFilter.setAuthenticationManager(authenticationManager);
    return customAUthenticationFilter;
}
```

#### AuthenticationManager 사용 방법 - 직접 생성

```java
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
  http.authorizeHttpRequest(auth -> auth.anyRequest().authenticated())
      .formlogin(Customizer.withDefault)
      .addFilterBefore(customFilter(), UsernamePasswordAuthenticationFilter.class);
  return http.build();
}


@Bean // @Bean으로 선언이 가능하다.
public CustsomAuthenticationFilter customFilter() {
    List<AuthentcationProvider> list1 = List.of(new DaoAuthenticationProvider());
    ProviderManager parent = new ProviderManager(list1);
    List<AuthentcationProvider> list2 = List.of(new AnonymousAuthenticationProvider("key"), new CustomAuthenticationProvider());
    Provider authenticationManager = new ProviderManager(list2, parent);
    
    CustomAuthenticationFilter customAuthenticationFilter = new CustomAuthenticationFilter();
    customAuthenticationFilter.setAuthenticationManager(authenticationManager);
    
    return customAuthenticationFilter;
}
```

### Authentication Provider
* Authentication Provider
  * 사용자의 자격 증명을 확인하고 인증 과정을 관리하는 클래스로서 사용자가 시스템에 액세스 하기 위해 제공한 정보 (예: 아이디와 비밀번호)가 유효한지 검증하는 과정을 포함한다.
  * 다양한 유형의 인증 메커니즘을 지원할 수 있는데, 예를 들어 표준 사용자 이름과 비밀번호를 기반으로 한 인증, 토큰 기반 인증, 지문 인식 등을 처리할 수 있다.
  * 성공적인 인증 후에는 Authentication 객체를 반환하며 이 객체는 사용자의 신원 정보와 인증된 자격 증명을 포함한다.
  * 인증 과정 중에 문제가 발생한 경우 AuthenticationException과 같은 예외를 발생시켜 문제를 알리는 역할을 한다.

```java
public interface AuthenticationProvider {
    Authentication authenticate(Authentication authentication) throws AuthenticationException;
    boolean supports(Class<?> authentication);
}
```
* AuthenticationManager로부터 Authentication 객체를 전달 받아 인증을 수행한다.
* 인증을 수행할 수 있는 조건인지를 검사한다.

### UserDetailsService
* UserDetailsService의 주요 기능은 사용자의 관련된 상세 데이터를 로드하는 것이며, 사용자의 신원, 권한 자격 증명 등과 같은 정보를 포함할 수 있다.
* 이 인터페이스를 사용하는 클래스는 주로 AuthenticationProvider이며 사용자가 시스템에 존재하는지 여부와 사용자 데이터를 검색하고 인증 과정을 수행한다.

```java
public interface UserDetailsService {
    UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;
}
```
* 사용자의 이름을 통해 사용자 데이터를 검색하고, 해당 데이터를 UserDetails 객체로 반환한다.

### UserDetailsService 사용 방법

```java
import java.beans.Customizer;

@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
  AuthenticationManagerBuilder managerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
  managerBuilder.userDetailsService(customUserDetailsService());
  http.userDetailsService(customUserDetailsService());

  http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
          .formLogin(Customizer.withDefault());
  return http.build();
}

@Bean
public UserDetailsService customUserDetailsService() {
    return new CustomUserDetailsService();
}
```
* UserDetailsService만 커스터 마이징 할 경우 위와 같이 적용하면 된다.
* AuthenticationProvider와 함께 커스터 마이징 할 경우 AuthenticationProvider에 직접 주입해서 사용한다.
* Bean으로 설정하면 자동 주입해준다.


### UserDetailsService
* 사용자의 기본 정보를 저장하는 인터페이스로서 Spring Security에서 사용하는 사용자 타입이다.
* 저장된 사용자 정보는 추후에 인증 절차에 사용되기 위해 Authentication 객체에 포함되며 구현체로서 User 클래스가 제공된다.

```java
public interface UserDetails extends Serializable {
    Collection<? extends GrantedAuthority> getAuthorities();

    String getPassword();

    String getUsername();

    default boolean isAccountNonExpired() {
        return true;
    }

    default boolean isAccountNonLocked() {
        return true;
    }

    default boolean isCredentialsNonExpired() {
        return true;
    }

    default boolean isEnabled() {
        return true;
    }
}
```
* getAuthorities(): 사용자에게 부여된 권한을 반환하며 null을 반환할 수 없다.
* getPassword(): 사용자 인증에 사용된 비밀번호를 반환한다.
* getUsername(): 사용자 인증에 사용된 사용자 이름을 반환하며 null을 반환할 수 없다.
* isAccountNonExpired(): 사용자 계정의 유효 기간이 지났는지를 나타내며 기간이 만료된 계정은 인증 할 수 없다.
* isAccountNonLocked(): 사용자가 잠겨있는지 아닌지를 나타내며 잠긴 사용자는 인증할 수 없다.
* isCredentialsNonExpired(): 사용자의 비밀번호 유효 기간이 지났는지를 확인하며 유효 기간이 지난 비밀번호는 인증할 수 없다.
* isEnabled(): 사용자가 활성화 되어있는지 비활성화 되어있는지 나타내며 비활성화된 사용자는 인증할 수 없다.

---

## 인증 상태 영속성
### SecurityContextRepository / SecurityContextHolderFilter
* SecurityContextRepository
  * 스프링 시큐리티에서 사용자가 인증을 한 이후 요청에 대해 계속 사용자의 인증을 유지하기 위해 사용되는 클래스이다.
  * 인증 상태의 영속 메커니즘은 사용자가 인증을 하게 되면 해당 사용자의 인증 정보와 권한이 SecurityContext에 저장되고 HttpSession을 통해 요청 간 영속성이 이루어 지는 방식이다.


```java
public interface SecurityContextRepository {
    /** @deprecated */
    @Deprecated
    SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder);

    default DeferredSecurityContext loadDeferredContext(HttpServletRequest request) {
        Supplier<SecurityContext> supplier = () -> {
            return this.loadContext(new HttpRequestResponseHolder(request, (HttpServletResponse)null));
        };
        return new SupplierDeferredSecurityContext(SingletonSupplier.of(supplier), SecurityContextHolder.getContextHolderStrategy());
    }

    void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response);

    boolean containsContext(HttpServletRequest request);
}
```
* loadDeferredContext: 로딩을 지연시켜 필요 시점에 SecurityContext를 가져온다.
* saveContext: 인증 요청 완료 시 보안 컨텍스트를 저장한다.
* containsContext: 현재 사용자를 위한 보안 컨텍스트가 저장소에 있는지 여부 조회


* HttpSessionSecurityContextRepository - 요청 간에 HttpSession에 보안 컨텍스트를 저장한다. 후속 요청 시 컨텍스트 영속성을 유지 한다.
* RequestAttributeSecurityContextRepository - ServletRequest에 보안 컨텍스트를 저장한다. 후속 요청 시 컨텍스트 영속성을 유지할 수 없다.
* NullSecurityContextRepository - 세션을 사용하지 않는 인증(JWT, OAuth2) 일 경우 사용하며 컨텍스트 관련 아무런 처리를 하지 않는다.
* DelegatingSecurityContextRepository - RequestAttributeSecurityContextRepository와 HttpSessionSecurityContextRepository를 동시에 사용할 수있도록 위임된 클래스로서 초기화 시 기본으로 설정된다.


* SecurityContextHolderFilter
  * SecurityContextRepository를 사용하여 SecurityContext를 얻고 이를 SecurityContextHolder에 설정하는 필터 클래스이다.
  * 이 필터 클래스는 SeucirtContextRepository.saveContext()를 강제로 실행시키지 않고 사용자가 명시적으로 호출되어야 SecurityContext를 저장할 수 있는데 이는 SecurityContextPersistenceFilter와 다른 점이다.
  * 인증이 지속되어야 하는지 각 인증 메커니즘이 독립적으로 선택할 수 있게 하여 더 나은 유연성을 제공하고 HttpSession에 필요할 때만 저장함으로써 성능을 향상시킨다.

* SecurityContext 생성, 저장, 삭제
  1. 익명 사용자
     * SecurityContextRepository를 사용하여 새로운 SecurityContext 객체를 생성하여 SecurityContextHolder에 저장 후 다음 필터로 전달.
     * AnonymousAuthenticationFilter에서 AnonymousAuthenticationToken 객체를 SecurityContext에 저장
  2. 인증 요청
     * SecurityContextRepository를 사용하여 새로운 SecurityContext 객체를 생성. SecurityContextHolder에 저장 후 다음 필터로 전달
     * UsernamePasswordAuthenticationFilter에서 인증 성공 후 SecurityContext에 UsernamePasswordAuthentication 객체를 SecurityContext에 저장
     * SecurityContextRepository를 사용하여 HttpSession에 SecurityContext를 저장
  3. 인증 후 요청
     * SecurityContextRepository를 사용하여 HttpSession에 SecurityContext 꺼내어 SecurityContextHolder에 저장 후 다음 필터로 전달
     * SecurityContext 안에 Authentication 객체가 존재하면 계속 인증을 유지 한다.
  4. 클라이언트 응답 시 공통
     * SecurityContextHolder.clearContext()로 컨텍스트를 삭제한다.(스레드 풀의 스레드일 경우 반드시 필요)

### securityContext() API
```java
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http.securityContext(securityContext -> securityContext.requireExplictSave(true));
    // SecurityContext를 명시적으로 저장할 것인지 아닌지 여부 설정, 기본 값은 true
    // true이면 SecurityContextHolderFilter, false이면 SecuirtContextPersistanceFilter가 실행된다.
    return http.build();
}
```
* 현재 SecurityContextPersistanceFilter는 Deprecated 되었기 때문에 레거시 시스템 외에는 SecurityContextHolderFilter를 사용하면 된다.

### CustomAuthenticationFilter & SecurityContextRepository
* 커스텀 한 인증 필터를 구현할 경우 인증이 완료된 후 SecurityContext를 SecurityContextHolder에 설정한 후 securityContextRepository에 저장하기 위한 코드를 명시적으로 작성해 주어야 한다.
`securityContextHolderStrategy.setContext(context);`, `securityContextRepository.saveContext(context);`
* securityContextRepository는 HttpSessionSecurityRepository 혹은 DelegatingSecurityContextRepository를 사용하면 된다.

### 스프링 MVC 인증 구현
* 스프링 시큐리티 필터에 의존하는 대신 수동으로 사용자를 인증하는 경우 스프링 MVC 컨트롤러 엔드포인트를 사용할 수 있다.
* 요청 간에 인증을 저장하고 싶다면 HttpSessionSecurityContextRepository를 사용하여 인증 상태를 저장할 수 있다.

```java
private final SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();

@PostMapping("/login")
public void login(@RequestBody LoginRequest loginRequest, HttpServletRequest request, HttpServletResponse response) {
    // 사용자 이름과 비밀번호를 담은 인증 객체를 생성한다.
    UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.unauthenticated(loginRequest.getUsername(), loginRequest.getPassword());

    // 인증을 시도하고 최종 인증 결과를 반환한다.
    Authentication authentication = authenticationManager.authentication(token);
    
    SecurityContext securityContext = SecurityContextHolder.getContextHolderStrategy().createEmptyContext();
    // 인증 결과를 컨텍스트에 저장한다.
    securityContext.setAuthentication(authentication);

    // 컨텍스트를 ThreadLocal에 저장한다.
    SecurityContextHolder.setContext(securityContext);

    // 컨텍스트를 세션에 저장해서 인증 상태를 영속한다.
    securityContextRepository.saveContext(securityContext, request, response);
}
```
---

## 세션 관리
### 동시 세션 제어
* 동시 세션 제어는 사용자가 동시에 여러 세션을 생성하는 것을 관리하는 것이다.
* 이 전략은 사용자의 인증 후에 활성화된 세션의 수가 설정된 maximumSessions 값과 비교하여 제어 여부를 결정한다.
 
#### 동시 세션 제어 2가지 유형
1. 사용자 세션 강제 만료
   * 최대 허용 개수만큼 동시 인증이 가능하고 그 외 이전 사용자의 세션을 만료시킨다.
2. 사용자 인증 차단 시도
   * 최대 허용 개수만큼 동시 인증이 가능하고 그 외 사용자의 인증 시도를 차단한다.

#### sessionManagement() API - 동시 세션 제어
```java
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throw Exception {
    http.sessionManagement(session -> session
        .invalidSessionUrl("/invalidSessionUrl")    // 이미 만료된 세션으로 요청을 하는 사용자를 특정 엔드포인트로 리다이렉션할 URL을 지정한다.
        .maximumSession(1)                          // 사용자당 최대 세션 수를 제어한다. 기본값은 무제한 세션을 허용한다.
        .maxSessionPreventsLogin(true)              // true이면 최대 세션 수에 도달 했을 때 사용자의 인증을 방지 한다. false(기본설정)이면 인증하는 사용자에게 접근을 허용하고 기존 사용자의 세션은 만료된다.
        .expiredUrl("/expired")                     // 세션을 만료하고 나서 리다이렉션 할 URL을 지정한다.
    );
    
    return http.build();
}
```
### 세션 고정 보호 전략
* 세션 고정 공격은 악의적인 공격자가 사이트에 접근하여 세션을 생성한 다음 다른 사용자가 같은 세션으로 로그인 하도록 유도하는 위험을 말한다.
* 스프링 시큐리티는 사용자가 로그인 할 때 새로운 세션을 생성하거나 세션 ID를 변경함으로써 이러한 공격에 자동으로 대응한다.

#### sessionManagement() API - 세션 고정 보호
```java
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throw Exception {
    http.sessionManagement(session -> session
            .sessionFixation(sessionFixation -> sessionFixation.newSession())
    );
    
    return http.build();
}
```
#### 세션 고정 보호 전략
* changeSessionId()
  * 기존 세션을 유지하면서 세션 ID만 변경하여 인증 과정에서 세션 고정 공격을 방지하는 방식이다. 기본값으로 설정되어있다.
* newSession()
  * 새로운 세션을 생성하고 기존 세션 데이터를 복사하지 않는 방식이다(SPRING_SECURITY_로 시작하는 속성은 복사한다.)
* migrateSession()
  * 새로운 세션을 생성하고 모든 기존 세션 속성을 새 세션에 복제한다.
* none()
  * 기존 세션을 그대로 사용한다.

### 세션 생성 정책
* 스프링 시큐리티에서는 인증된 사용자에 대한 세션 생성 정책을 설정하여 어떻게 세션을 관리할지 결정할 수 있으며 이 정책은 SessionCreationPolicy로 설정된다.

### 세션 생성 정책 전략
* SessionCreationPolicy.ALWAYS
  * 인증 여부에 상관없이 항상 세션을 생성한다.
  * ForceEagerSessionCreationFilter 클래스를 추가 구성하고 세션을 강제로 생성시킨다.
* SessionCreationPolicy.NEVER
  * 스프링 시큐리티가 세션을 생성하지 않지만 애플리케이션이 이미 생성한 세션은 사용할 수 있다.
* SessionCreationPolicy.IF_REQUIRE
  * 필요한 경우에만 세션을 생성한다. 예를 들어 인증이 필요한 자원에 접근할 때 세션을 생성한다.
* SessionCreationPolicy.STATELESS
  * 세션을 전혀 생성하거나 사용하지 않는다.
  * 인증 필터는 인증 완료 후 SecurityContext를 세션에 저장하지 않으며 JWT와 같이 세션을 사용하지 않는 방식으로 인증을 관리할 때 유용할 수 있다.
  * SecurityContextHolderFilter는 세션 단위가 아닌 요청 단위로 항상 새로운 SecurityContext 객체를 생성하므로 컨텍스트 영속성이 유지되지 않는다.

### sessionManagement() API - 세션 생성 정책
```java
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throw Exception {
    http.sessionManagement(session -> session
            .sessionCreationPolicy(sessionCreation.STATELESS)
    );
    
    return http.build();
}
```
### STATELESS 설정에도 세션이 생성될 수 있다
* 스프링 시큐리티에서 CSRF 기능이 활성화 되어있고 CSRF 기능이 수행 될 경우 사용자의 세션을 생성해서 CSRF 토큰을 저장하게 된다.
* 세션은 생성되지만 CSRF 기능을 위해서 사용ㄷ될 뿐 인증 프로세스의 SecurityContext 영속성에 영향을 미치지 않는다.

### SessionManagementFilter / ConcurrentSessionFilter
* SessionManagementFilter
  * 요청이 시작된 이후 사용자가 인증되었는지 감지하고, 인증된 경우에는 세션 고정 보호 메커니즘을 활성화하거나 동시 다중 로그인을 확인하는 등 세션 관련 활동을 수행 하기 위해 설정 된 세션 인증 전략(SessionAuthentication)을 호출하는 필터 클래스이다.
  * 스프링 시큐리티 6 이상에서는 SessionManagementFilter가 기본적으로 설정 되지 않으며 세션관리 API를 설정해 생성할 수 있다.
 
* ConcurrentSessionFilter
  * 각 요청에 대해 SessionRegistry에서 SessionInformation을 검색하고 세션이 만료 표시되었는지 확인하고 만료로 표시된 경우 로그아웃 처리를 수행한다(세션 무효화)
  * 각 요청에 대해 SessionRegistry.refreshRequest(String)를 호출하여 등록된 세션들이 항상 '미지막 업데이트' 날짜/시간을 가지도록 한다.

---

## 예외 처리 - exceptionHandling()
* 예외 처리는 필터 체인 내에서 발생하는 예외를 의미하며 크게 인증예외(AuthenticationException)와 인가예외(AccessDeniedException)로 나눌 수 있다.
* 예외를 처리하는 필터로서 ExceptionTranslationFilter가 사용 되며 사용자의 인증 및 인가 상태에 따라 로그인 재시도, 401, 403 코드 등으로 응답할 수 있다.

### 예외 처리 유형
* AuthenticationException
  1. SecurityContext에서 인증 정보 삭제 - 기존의 Authentication 이 더 이상 유효하지 않다고 판단하고 Authentication을 초기화 한다.
  2. AuthenticationEntryPoint 호출
     * AuthenticationException이 감지되면 필터는 authenticationEntryPoint를 싱행하고 이를 통해 인증 실패를 공통적으로 처리할 수 있으며 일반적으로 인증을 시도할 수 있는 화면으로 이동한다.
  3. 인증 프로세스의 요청 정보를 저장하고 검색
     * RequestCache & SavedRequest - 인증 프로세스 동안 전달되는 요청을 세션 혹은 쿠키에 저장
     * 사용자가 인증을 완료한 후 요청을 검색하여 재 사용할 수 있다. 기본 구현은 HttpSessionRequestCache이다.
  
* AccessDeniedException
  * AccessDeniedHandler 호출
    * AccessDeniedException이 감지되면 필터는 사용자가 익명 사용자가 익명 사용자인지 여부를 판단하고 익명 사용자인 경우 인증 예외처리가 실행되고 익명 사용자가 아닌 경우 필터는 AccessDeniedHandler에게 위임한다.

### exceptionHandling() API
```java
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http.exceptionHandling(exception -> exception
            .authenticationEntryPoint((request, response, authException) -> {   // 커스텀하게 사용할 AuthenticationEntryPoint를 설정한다.
                System.out.println(authException.getMessage());
            })
            .accessDeniedHandler(request, response, accessDeniedException -> {  // 커스텀하게 사용할 AccessDeniedHandler를 설정한다.
                System.out.println(accessDeniedException.getMessage());
            })
    );
    
    return http.build();
}
```
* AuthenticationEntryPoint는 인증 프로세스 마다 기본적으로 제공되는 클래스들이 설정된다.
  * UsernamePasswordAuthenticationFilter - LoginUrlAuthenticationEntryPoint
  * BasicAuthenticationFilter - BasicAuthenticationEntryPoint
  * 아무런 인증 프로세스가 설정 되지 않으면 기본적으로 Http403ForbiddenEntryPoint가 사용된다.
  * 사용자 정의 AuthenticationEntryPoint 구현이 가장 우선적으로 수행되며 이 때는 기본 로그인 페이지 생성이 무시된다.
  
* AccessDeniedHandler는 기본적으로 AccessDeniedHandlerImple 클래스가 사용된다.

---

## 악용 보호
### CORS (Cross Origin Resource Sharing)
* 웹에서는 보안을 위해 기본적으로 한 웹 페이지(출처A)에서 다른 웹페이지(출처B)의 데이터를 직접 불러 오는 것을 제한하는데 이를 '동일 출처 정책(Same-Origin Policy)'라고 한다.
* 만약 다른 출처의 리소스를 안전하게 사용하고자 CORS가 등장하며 CORS는 특별한 HTTP 헤더를 통해 한 웹 페이지가 다른 출처의 리소스에 접근할 수 있또록 '허가'를 구하는 방법이다.
  즉, 웹 애플리케이션이 다른 출처의 데이터를 사용하고자 할 때, 브라우저가 그 요청을 대신해서 해당 데이터를 사용해도 되는지 다른 출처에게 물어보는 것이라 할 수 있다.
* 출처를 비교하는 로직은 서버에 구현된 스펙이 아닌 브라우저에 구현된 스펙 기준으로 처리되며 부라우저는 클라이언트의 요청 헤더와 서버의 응답헤더를 비교해서 최종 응답을 결정 한다.
* 두개의 출처를 비교하는 방법은 URL의 구성요소 중 Protocol, Host, Port 이 세가지가 동일한지 확인하면 되고 나머지는 틀려도 상관없다.


* https://domain-a.com의 프론트 엔드 Javascript 코드가 XHLHttpRequest를 사용하여 https://domain-b.com/data.json을 요청하는 경우 보안 상의 이유로, 브라우저는 스크립트에서 시작한 교차 출처 HTTP 요청을 제한한다.
* XMLHttpRequest와 Fetch API는 동일 출처 정책을 따르기 때문에 이 API를 사용하는 웹 애플리케이션은 자신의 출처와 동일한 리소스만 불러올 수 있으며, 다른 출처의 리소스를 불러오러면 그 출처에서 올바른 CORS 헤더를 포함한 응답을 반환해야 한다.

1. Simple Request
  * Simple Request는 예비 요청(Preflight) 과정 없이 자동 CORS가 작동하여 서버에 본 요청을 한 후, 서버가 응답의 헤더에 Access-Control-Allow-Origin과 같은 값을 전송하면 브라우저가 서로 비교 후 CORS 정책 위반 여부를 검사하는 방식이다.
  * 제약 사항
    * GET, POST, HEAD중의 한가지 Method를 사용해야 한다.
    * 헤더는 Accept, Accept-Language, Content-Language, Content-Type, DPR, Downlink, Save-Data, Viewport-Width Width만 가능하고 Custom Header는 허용되지 않는다.
    * Content-type은 application/x-www-form-urlencoded, multipart/form-data, text/pain만 가능하다.
2. Preflight Request
  * 브라우저는 요청을 한번에 보내지 않고, 예비 요청과 본 요청으로 나누어 서버에 전달하는데 브라우저가 예비요청을 보내는 것을  Preflight라고 하며 이 예비요청의 메소드에는 OPTIONS가 사용된다.
  * 예비요청의 역할은 본 요청을 보내기 전에 브라우저 스스로 안전한 요청인지 확인하는 것으로 요청 사항이 SimpleRequest에 해당하지 않을 경우 브라우저가 PreflightRequest를 실행한다.

#### CORS 해결 - 서버에서 Access-Control-Allow 세팅
* Access-Control-Allow-Origin: 헤더에 작성된 출처만 브라우저가 로스스를 접근할 수 있도록 허용한다.
  * *(와일드카드), https://example.com
* Access-Control-Allow-Methods: Preflight request에 대한 응답으로 실제 요청 중에 사용할 수있는 메서드를 나타낸다.
  * 기본값은 GET, POST, HEAD, OPTIONS, *
* Access-Control-Allow-Headers: Preflight request에 대한 응답으로 실제 요청 중에 사용할 수 있는 헤더 필드이름을 나타낸다.
  * 기본값은 Origin, Access, X-Requested-With, Content-Type, Access-Control-Request-Method, Access-Control-Request-Headers, Custom Header *
* Access-Control-Allow-Credentials: 실제 요청에 쿠키나 인증 등의 사용자 자격 증명이 포함될 수 있음을 나타낸다. Client의 credientials:include 옵션일 경우 true는 필수
* Access-Control-Max-Age: preflight 요청 결과를 캐시 할 수 있는 시간을 나타내는 것으로 해당 시간동안은 preflight 요청을 다시 하지 않게 된다.

#### cors(), CorsFilter
* CORS의 사전 요청(preflight)에는 쿠키(JSESSIONID)가 포함되어 있지 않기 때문에 SpringSecurity 이전에 처리되어야 한다.
* 사전 요청에 쿠키가 없고 SpringSecurity가 가장 먼저 처리되면 요청은 사용자가 인증되지 않았다고 판단하고 거부할 수 있다.
* CORS가 먼저 처리되도록 하기 위해 CorsFilter를 사용할 수 있으며 CorsFilter에 CorsConfigurationSource를 제공함으로써 SpringSecurity와 통합할 수 있다.

```java
@Bean
SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
  http.cors(cors -> cors.configurationSource(corsConfigurationSource())); // 커스텀하게 사용할 CorsConfigurationSource를 설정한다.
                                                                          // CorsConfigurationSource를 설정하지 않으면 SpringMVC의 CORS 구성을 사용한다.
  return http.build();
}

@Bean
public CorsConfigurationSource configurationSource() {
    CorsConfiguration configuration = new CorsConfiguration();
    configuration.addAllowdOrigin("https://example.com");
    configuration.addAllowdMethod("GET", "POST");
    configuration.setAllowCredintials(true);
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorConfiguration("/**",  configuration);
    return source;
}
```
### CSRF(Cross Site Request Forgery, 사이트간 요청 위조)
* 웹 애플리케이션의 보안 취약점으로 공격자가 사용자로 하여금 이미 인증된 다른 사이트에 대해 원치 않는 작업을 수행하게 만드는 기법을 말한다.
* 이 공격은 사용자의 브라우저가 자동으로 보낼 수 있는 인증정보, 예를 들어 쿠키나 기본 인증 세션을 이용하여 사용자가 의도하지 않은 요청을 서버로 전송하게 만든다.
* 이는 사용자가 로그인한 상태에서 악의적인 웹사이트를 방문하거나 이메일 등을 통해 악의적인 링크를 클릭할 때 발생할 수 있다.

### CSRF 기능 화성화

```java
import java.beans.Customizer;

@Bean
SecurityFilterChain defaultFilterChain(HttpSecurity http) {
  http.csrf(Customizer.withDefault());  // csrf의 기능을 활성화 한다. 별도로 설정하지 않아도 활성화 상태로 초기화 된다.
  return http.build();
}
```
* 토큰은 서버에  의해 생성되어 클라이언트의 세션에 저장되고 폼을 통해 서버로 전송되는 모든 변경 요청에 포함되어야 하며 서버는 이 토큰을 검증하여 요청의 유효성을 확인한다.
* 기본 설정은 'GET', 'HEAD', 'TRACE', 'OPTIONS'와 같은 안전한 메서드를 무시하고 'POST', 'PUT', 'DELETE'와 같은 변경 요청 메서드에 대해서만 CSRF 토큰 검사를 수행한다.
* 중요한 점은 실제 CSRF 토큰이 브라우저에 의해 자동으로 포함되지 않은 요청 부분에 위치해야 한다는 것으로 HTTP 매개변수나 헤더에 실제 CSRF 토큰을 요구하는 것이 CSRF 공격을 방지하는데 효과적이라 할 수 있다.
* 반면에 쿠키에 토큰을 요구하는 것은 브라우저가 쿠키를 자동으로 요청에 포함시키기 때문에 효과적이지 않다고 볼 수 있다.

#### CSRF 기능 비활성화
* CSRF 기능 전체 비활성화
```java
import java.beans.Customizer;

@Bean
SecurityFilterChain defaultFilterChain(HttpSecurity http) {
  http.csrf(csrf ->csrf.disabled());
  return http.build();
}
```

* CSRF 보호가 필요하지 않은 특정 엔드포인트만 비활성화
```java
@Bean
SecurityFilterChain defaultFilterChain(HttpSecurity http) {
  http.csrf(csrf ->csrf.ignoringRequestMatchers("/api/*"));
  return http.build();
}
```

### CSRF 토큰 유지 - CsrfTokenRepository
* CsrfToken은 CsrfTokenRepository를 사용하여 영속화 하며 HttpSessionCsrfTokenRepository와 CookieCsrfTokenRepository를 지원한다.
* 두 군데 중 원하는 위치에 토큰을 저장하도록 설정을 통해 지정할 수 있다.

1. 세션에 토큰 저장 - HttpSessionCsrfTokenRepository
   * 기본적으로 토큰을 세션에 저장하기 위해 HttpSessionCsrfTokenRepository를 사용한다.
   * HttpSessionCsrfTokenRepository는 기본적으로 HTTP 요청 헤더인 X-CSRF-TOKEN 또는 요청 매개변수인 _csrf에서 토큰을 읽는다.

```java
@Bean
SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) {
  HttpSessionCsrfTokenRepository csrfTokenRepository = new HttpSessionCsrfTokenRepository();
  http.csrf(csrf -> csrf.csrfTokenRepository(csrfTokenRepository));
  return http.build();
}
```


2. 쿠키에 토큰 저장 - CookieCsrfTokenRepository
   * Javascript 기반 애플리케이션을 지원하기 위해 CsrfToken을 쿠키에 유지할 수 있으며 구현체로 CookieCsrfTokenRepsitory를 사용할 수 있다.
   * CookieCsrfTokenRepository는 기본적으로 XSRF-TOKEN 명을 가진 쿠키에 작성하고 HTTP 요청 헤더인 X-XSRFT-TOKEN 또는 요청 매개변수인 _csrf에서 읽는다.
   * Javascript에서 쿠키를 읽을 수 있도록 HttpOnly를 명시적으로 false로 설정할 수 있다.
   * Javascript로 직접 쿠키를 읽을 필요가 없는 경우 보안을 개선하기 위해 HttpOnly를 생략하는 것이 좋다.

```java

@Bean
SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) {
  CookieCsrfTokenRepository cookieCsrfTokenRepository = new CookieCsrfTokenRepository();
  // 둘중 하나만 선택, 
  http.csrf(csrf -> csrf.csrfTokenRepository(csrfTokenRepository));
  http.csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse));
  return http.build();
}
```

#### CSRF 토큰 처리 - CsrfTokenRequestHandler
* CsrfToken은 CsrfTokenHandler를 사용하요 토큰을 생성하고 응답하고 HTTP헤더 또는 요청 매개변수로부터 토큰의 유효성을 검증하도록 한다.
* XorCsrfTokenRequestAttributeHandler와 CsrfTokenRequestAttributeHandler를 제공하며 사용자의 정의 핸들러를 구현할 수 있다.

```java
@Bean
SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
    XorCsrfTokenRequestAttributeHandler csrfTokenHandler = new XorCsrfTokenRequestAttributeHandler();
    http.csrf(csrf -> csrf.csrfTokenRequestHandler(csrfTokenHandler));
    return http.build();
}
```
* "_csrf" 및 CsrfToken.class.getName() 명으로 HttpServletReqeust 속성에 CsrfToken을 저장하며 HttpServletRequest으로부터 CsrfToken을 꺼내어 참조할 수 있다.
* 토큰 값을 요청 헤더 (기본적으로 X-CSRF-TOKEN 또는 X-XSRF-TOKEN 중 하나) 또는 요청 매개변수 (_csrf)중 하나로부터 토큰의 유효성을 비교 및 검증을 해결 한다.
* 클라이언트의 매 요청마다 CSRF 토큰 값(UUID)에 난수를 인코딩하여 변경한 CsrfToken이 반환되도록 보장한다. 세션에 저장된 원본 토큰 값은 그대로 유지한다.
* 헤더 값 또는 요청 매개변수로 전달된 인코딩 된 토큰은 원본 토큰을 얻기 위해 디코딩되며, 그런 다음 세션 혹은 쿠키에 저장된 영구적인 CsrfToken과 비교된다.

#### CSRF 토큰 지연 로딩
* 기본적으로 SpringSecurity는 CsrfToken을 필요할 때까지 로딩을 지연시키는 전략을 사용한다. 그러므로 CsrfToken은 HttpSession에 저장되어있기 때문에 매 요청마다 세션으로부터 CsrfToken을 로드할 필요가 없어져 성능을 향상시킬 수 있다.
* CsrfToken은 POST와 같은 안전하지 않은 HTTP 메서드를 사용하여 요청이 발생할 때와 CSRF 토큰을 응답에 렌더링하는 모든 요청에서  필요하기 때문에 그 외 요청에는 지연로딩 하는 것이 권장된다.
```java
@Bean
SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
  XorCsrfTokenRequestAttributeHandler csrfTokenHandler = new XorCsrfTokenRequestAttributeHandler();
  csrfTokenHandler.setCsrfRequestAttributeName(null); // 지연된 토큰을 사용하지 않고 CsrfToken을 모든 요청마다 로드한다.
  http.csrf(csrf -> csrf.csrfTokenRequestHandler(csrfTokenHandler));
  return http.build();
}
```

### CSRF 통합
* CSRF 공격을 방지하기 위한 토큰 패턴을 사용하려면 실제 CSRF 토큰을 HTTP 요청에 포함해야 한다.
* 그래서 브라우저에 의해 HTTP 요청에 자동으로 포함되지 않는 요청 부분(폼 매개변수, HTTP 헤더 또는 기타 부분) 중에 하나 포함되어야 한다.
* 클라이언트 애플리케이션이 CSRF로 보호된 백엔드 애플리케이션과 통합하는 여러 가지 방법을 살펴보자.

#### HTML Forms
* HTML Form을 서버에 제출하려면 CSRF 토큰을 hidden 값으로 Form에 포함해야 한다
```html
<form action="/memberJoin" method="post">
  <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}" />
</form>
```
* Form에 실제 CSRF 토큰을 자동으로 포함하는 뷰는 다음과 같다.
  * Thymeleaf
  * Spring의 form태그 라이브러리

#### Javascript Application
* Single Page Application
  1. CookieCsrfTokenRepository.withHttpOnlyFalse를 사용해서 클라이언트가 서버가 발행한 쿠키로부터 CSRF 토큰을 읽을 수 있도록 한다.
  2. 사용자 정의 CsrfTokenRequestHandler를 만들어 클라이언트가 요청 헤더나 요청 파라미터로 CSRF 토큰을 제출할 경우 이를 검증하도록 구현한다.
  3. 클라이언트의 요청에 대해 CSRF 토큰 쿠키에 렌더링해서 응답할 수 있도록 필터를 구현한다.
* Multi Page Application
  1. Javascript가 각 페이지에서 로드되는 멀티 페이지 애플리케이션의 경우 CSRF 토큰을 쿠키에 노출시키는 대신 HTML 메타 태그 내에 CSRF 토큰을 포함시킬 수 있다.
```html
<!DOCTYPE html>
<html>
    <meta name="_csrf" content="${_csrf.token}"/>
    <meta name="_csrf.header" content="${_csrf.headerName}"/>
</html>
```

### SameSite 
* SameSite는 최신 방식의 CSRF 공격 방어 방법 중 하나로서 서버가 쿠키를 설정할 때 SameSite 속성을 지정하여 크로스 사이트 간 스크립트 전송에 대한 제어를 핸들링할 수 있다.
* SpringSecurity는 세션 쿠키의 생성을 직접 제어하지 않기 때문에 SameSite 속성에 대한 지원을 제공하지 않지만 Spring Session은 SameSite 속성을 지원한다.

#### SameSite 속성
* Strict
  * 동일 사이트에서 오는 모든 요청에 쿠키가 포함되고 크로스 사이트간 HTTP 요청에 쿠키가 포함되지 않는다.
* Lax(기본 설정)
  * 동일 사이트에 오거나 Top Level Navigation에서 오는 요청 및 메소드가 읽기 전용인 경우 쿠키가 전송되고 그렇지 않으면 HTTP 요청에 쿠키가 포함되지 않는다.
  * 사용자가 링크 (`<a>`)를 클릭하거나 windows.location.replace, 302 리다이렉트 등의 이동이 포함된다. 그러나 `<iframe>`이나 `<img>`를 문서에 삽입, AJAX 통신등은 쿠키가 전송되지 않는다.
* None
  * 동일 사이트 및 크로스 사이트 요청의 경우에도 쿠키가 전송된다. 이모드에서는 HTTPS에 의한 Secure 쿠키로 설정되어야 한다.

#### Spring Session으로 SameSite 적용하기
`implementation group: 'org.springframework.session', name: 'spring-session-core', version: '3.2.1'`

```java
import java.util.concurrent.ConcurrentHashMap;

@Configuration
@EnableSpringHttpSession
public class HttpSessionConfig {
  @Bean
  public CookieSerializer cookieSerializer() {
    DefaultCookieSerializer serializer = new DefaultCookieSerializer();
    serializer.setUseSecuredCookie(true);
    serializer.setUseHttpOnlyCookie(true);
    serializer.setSameSite("Lax");
    return serializer;
  }

  @Bean
  public SessionRepository<MapSession> sessionRepository() {
    return new MapSessionRepository(new ConcurrentHashMap<>());
  }
}
```

---
## 인가 프로세스
### 요청 기반 권한 부여 (Request Based Authorization) - HttpSecurity.authorizeHttpRequest()
```java
@Bean
SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(authorize -> authorize
            .anyRequest().authenticated() // 애플리케이션의 모든 엔드포인트가 최소한 인증된 보안 컨텍스트가 있어야 한다.
    );
    
    return http.build();
}
```
* authorizeHttpRequests()는 사용자의 자원접근을 위한 요청 엔드포인트와 접근에 필요한 권한을 매핑시키기 위한 규칙을 설정하는 것으로서 서블릿 기반 엔드포인트에 접근하려면 authorizeHttpReqeust()에 해당 규칙들을 포함해야 한다.
* authorizeHttpRequests()를 통해 요청과 권한 규칙이 설정되면 내부적으로 AuthorizationFilter가 요청에 대한 권한 검사 및 승인 작업을 수행한다.

#### authorizeHttpRequests() API
* requestMatchers()
  * requestMatchers 메소드는 HTTP 요청의 URL 패턴, HTTP 메소드, 요청 파라미터 등을 기반으로 어떤 요청에 대해서는 특정 보안 설정을 적용하고 다른 요청에 대해서는 적용하지 않도록 세밀하게 제어할 수 있게 해준다.
  * 예를 들어 특정 API 경로에만 CSRF 보호를 적용하거나, 특정 경로에 대해 인증을 요구하지 않도록 설정할 수 있다. 이를 통해 애플리케이션의 보안 요구 사항에 맞춰 유연한 보안정책을 구성핤수 있다.

> 1. requestMatchers(String... urlPattern)      
>    * 보호가 필요한 자원 경로를 한 개 이상 정의 한다.
> 2. requestMatchers(RequestMatcher... requestMatchers)
>    * 보호가 필요한 자원 경로를 한 개 이상 정의한다. AnyPathRequestMatcher, MvcRequestMatcher 등의 구현체를 사용할 수 있다.
> 3. requestMatchers(HttpMethod method, String... urlPatterns)
>    * Http Method와 보호가 필요한 자원 경로를 한 개 이상 정의 한다.

* 엔드 포인트 & 권한 부여
```java
requestMatchers("/admin").hasRole("ADMIN") // 요청 URL이 /admin 엔드포인트일 경우 ADMIN 권한이 필요
```

#### 보호 자원과 권한 규칙 설정하기
```java
http.authorizeHttpRequests(authorize -> authorize
        .requestMatcher("/user").hasAuthority("USER")       // 엔드 포인트와 권한 설정, 요청이 /user 엔드포인트 요청일 경우 USER 권한이 필요하다.
        .requestMatcher("/mypage/**").hasAuthority("USER")  // Ant 패턴을 사용할 수 있다. 요청이 /mypage 또는 그 하위 경로인 경우 USER 권한이 필요하다.
        .requestMatcher(RegexRequestMatcher.regexMatcher("/resource/[A-Za-z0-9]+")).hasAuthority("USER") // 정규 표현식을 사용할 수 있다.
        .requestMatcher(HttpMethod.GET, "/**").hasAuthority("read") //HTTP Method를 옵션으로 설정할 수 있다.
        .requestMatcher(HttpMethod.POST).hasAuthority("write")      //POST 방식의 모든 엔드포인트 요청은 write 권한을 필요로 한다.
        .requestMatcher(new AntPathRequestMatcher("/manager/**")).hasAuthority("MANAGER")   // 원하는 RequestMatcher를 직접 사용할 수 있다.
        .requestMatcher("/admin/**").hasAnyAuthority("ADMIN", "MANAGER")    // /admin/ 이하의 모든 요청은 ADMIN과 MANAGER 권한을 필요하다.
        .anyRequest().authenticated()   // 위에서 정의한 규칙 외 모든 엔드 포인트 요청은 인증을 필요로 한다.
);
```
#### 주의 사항
* 스프링 시큐리티는 클라이언트의 요청에 대하여 위에서 부터 아래로 나열된 순서대로 처리한다. 요청에 대하여 첫번째 일치만 적용 되고 다음순서로 넘어가지 않는다.
* /admin/**가 /admin/db 요청을 포함하므로 의도한 대로 규칙이 올바르게 적용 되지 않을 수 있다. 그렇기 때문에 엔드포인트 설정 시 좁은 범위의 경로를 먼저 정의하고 그것 보다 큰 범위의 경로를 다음으로 정의 해야 한다.

#### 권한 규칙 종류
* authenticated: 인증된 사용자의 접근을 허용 한다.
* fullyAuthenticated: 아이디와 패스워드로 인증된 사용자의 접근을 허용, rememberMe 인증은 제외 한다.
* anonymous: 익명사용자의 접근을 허용한다.
* rememberMe: 기억하기를 통해 인증된 사용자의 접근을 허용한다.
* permitAll: 요청에 승인이 필요하지 않은 공개 엔드포인트이며, 세션에서 Authentication을 검색하지 않는다.
* denyAll: 요청은 어떠한 경우에도 허용되지 않으며 세션에서 Authentication을 검색하지 않는다.
* access: 요청이 사용자 정의 AuthorizationManager를 사용하여 액세스를 결정한다.(표현식 문법 사용)
* hasAuthority: 사용자의 Authentication에는 지정된 권한과 일치하는 GrantedAuthority가 있어야 한다.
* hasRole: hasAuthority의 단축키로 ROLE_ 또는 기본접두사로 구성된다. ROLE_을 제외한 문자열을 파라미터로 전달.
* hasAnyAuthority: 사용자 Authentication에는 지정된 권한 중 하나와 일치하는 GrantedAuthority가 있어야 한다.
* hasAnyRole: hasAnyAuthority의 단축키로 ROLE_ 또는 기본 접두사로 구성된다. ROLE_을 제외한 문자열을 파라미터로 전달.

> 권한 규칙은 내부적으로 AuthorizationManager 클래스에 의해 재 구성되며 모든 요청은 Authroization에 설정된 권한 규칙에 따라 승인 혹은 거부된다.

### 표현식 및 커스텀 권한 구현
* 표현식 권한 규칙 설정
  * 스프링 시큐리티는 표현식을 사용해서 권한 규칙을 설정하도록 WebExpressionAuthorizationManager를 제공한다.
  * 표현식은 시큐리티가 제공하는 권한 규칙을 사용하거나 사용자가 표현식을 커스텀하게 구현해서 설정 가능하다.

* 사용 방법    
`requestMatchers().access(new WebExpressionAuthorizationManager("expression"))`

* 적용하기
```java
// 요청으로부터 값을 추출할 수 있다.
requestMatchers("/resource/{name}").access(new WebExpressionAuthorizationManager("#name == authentication.name"))

// 여러개의 권한 규칙을 조합할 수 있다.
requestMatchers("/admin/db").access(new webExpressionAuthorizationManager("hasAuthority('DB') or hasRole('ADMIN)"))
```

```java
requestMatchers("/admin/db").access(anyOf(hasAuthority("db"), hasRole("ADMIN")))
```

#### 커스텀 권한 표현식 구현

```java
import java.net.http.HttpRequest;

SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http, ApplicationContext context) throws Exeception {
  DefaultHttpSecurityExpressionHandler expressionHandler = new DefaultHttpSecurityExpressionHandler();
  expressionHandler.setApplicationContext(context);

  WebExpressionAuthorizationManager expressManager = new WebExpressionAuthorizationManager("@customWebSecurity.check(authentication, request)");
  expressManager.setExpressionHandler(expressManager);

  http.authorizeRequests(authorize -> authorize.requestMatchers("/resource/**").access(expressManager));

  return http.build();
}

@Component("customWebSecurity")
public class CustomWebSecurity {
  public boolean check(Authentication authentication, HttpRequest request) {
      return authentication.isAuthenticated(); // 사용자가 인증 되었는지를 검사
  }
}
```
* 사용자 정의 빈을 생성하고 새로운 표현식으로 사용할 메서드를 정의하고 권한 검사 로직을 구현한다.

#### 커스텀 RequestMatcher 구현
RequestMatcher의 mathcer 및 matchers 메서드를 사용하여 클라이언트의 요청 객체로부터 값을 검증하도록 커스텀한 RequestMatcher를 구현하고 requestMatchers() 메서드에 설정한다.

```java
public class CustomRequestMatcher implements RequestMatcher {
    private final String urlPattern;
    public CustomRequestMatcher(String urlPattern) {
        this.urlPattern = urlPattern;
    }
    
    @Override
    public boolean matchers(HttpServletRequest request) {
        String requestURI = request.getRequestURI();
        return requestURI.startsWith(urlPattern);
    }
}
```
```java
http.authorizeHttpRequest((authorize) -> authorize
        .requestMatchers(new CustomRequestMatcher("/api/**")).hasAuthority("USER")
        .anyRequests().authenticated());
```

#### 요청 기반 권한 부여 - HttpSecurity.securityMatcher()
* securityMatcher()
  * securityMatcher 메소드는 특정 패턴에 해당하는 요청에만 보안 규칙을 적용하도록 설정할 수 있으며 중복해서 정의할 경우 마지막에 설정한 것으로 대체한다.
  1. securityMatcher(String... urlPattern)
     * 특정 자원 보호가 필요한 경로를 정의한다.
  2. securityMatcher(RequestMatcher.. requestMatchers)
     * 특정 자원 보호가 필요한 경로를 정의한다. AntPathRequestMatcher, MvcRequestMatcher 등의 구현체를 사용할 수 있다.
  
* 패턴 설정
`http.securityMathcer("/api/**").authorizeHttpRequests(auth -> auth.requestMatcher(...))`
  * httpSecurity를 /api/로 시작하는 URL에만 적용하도록 구성한다.
  * SpringMVC가 클래스 경로에 있으면 MvcRequestMatcher가 사용되지 않고, 그렇지 않으면 AntPathRequestMatcher가 사용된다.

* securityMatchers()
  * 다중 설정 패턴
    * securityMatchers 메소드는 특정 패턴에 해당하는 요청을 단일이 아닌 다중 설정으로 구성해서 보안 규칙을 적용할 수 있으며 현재의 규칙은 이전의 규칙을 대체하지 않는다.
* 패턴 유형
```java
// 패턴1
http.securityMathcers((matcher) -> matcher.requestMatcher("/api/**", "/oauth/**"));

// 패턴2
http.securityMathcers((matcher) -> matcher.requestMatcher("/api/**").requestMatcher("/api/**"));

// 패턴3
http.securityMathcers((matcher) -> matcher.requestMatcher("/api/**"))
    .securityMathcers((matcher) -> matcher.requestMatcher("/api/**"));
```

#### 메서드 기반 권한 부여 - @PreAuthorize, @PostAuthorize
* 스프링 시큐리티는 요청 수준의 권한 부여뿐만아니라 메서드 수준에서의 권한 부여를 지원한다.
* 메서드 수준 권한 부여를 활성화 하기 위해서는 설정 클래스에 `@EnableMethodSecurity` 애노테이션을 추가해야 한다.
* SpEL(Spring Expression Language) 표현식을 사용하여 다양한 보안 조건을 정의할 수 있다.

#### @EnableMethodSecurity
```java
@EnableMethodSecurity
@Configuration
public class SecurityConfig { ... }
```

#### @PreAuthorize
* @PreAuthorize 애노테이션은 메서드가 실행되기 전에 특정한 보안 조건이 충족되는지 확인하는 데 사용되며 보통 서비스 또는 컨트롤러 레이어의 메소드에 적용되어 해당 메소드가 호출 되기 전에 사용자의 인증 정보와 권한을 검사한다.
```java
@PreAuthorize("hasAuthority('ROLE_ADMIN')")
public void adminOnlyMethod() {}

@PreAuthorize("hasAuthority('ROLE_ADMIN', 'ROLE_USER')")
public void adminOrUserMethod() {}

@PreAuthorize("isAuthenticated()")
public void authenticatedUserOnlyMethod() {}

@PreAuthorize("#id == authentication.name")
public void userSpecificMethod(String id) {}
```

#### @PostAuthorize
* @PostAuthorize 애노테이션은 메소드가 실행된 후에 보안 검사를 수행하는데 사용된다.
* @PreAuthorize와 달리 메소드 실행 후 결과에 대한 보안 조건을 검사하여 특정 조건을 만족하는 경우에만 결과를 받을 수 있도록 한다.
```java
@PostAuthorize("returnObject.owner == authentication.name")
public BancAccount getAccount(Long id) {
    // 계정을 반환하지만 계정의 소유자만 결과를 볼 수 있음
    return new BankAccount();
}

@PostAuthorize("hasAuthority('ROLE_ADMIN') and returnObject.isSecure")
public BancAccount getSecureAndAdminAccount() {
  // 계정을 반환하지만 계정이 기밀이고 사용자가 관리자일 경우에만 결과를 볼 수 있음
  return new BankAccount();
}

@PostAuthorize("returnObject != null and (returnObject.status === 'APPROVED' or hasAuthority('ROLE_ADMIN')")
public BancAccount updateRequestStatus() {
    return new BankAccount();
}
```

#### 메서드 기반 권한 부여 - @PreFilter, @PostFilter
* @PreFilter
  * @PreFilter 애노테이션은 메소드가 실행되기 전에 메소드에 전달된 컬렉션 타입의 파라미터에 대한 필터링을 수행하는데 사용된다.
  * @PreFilter 애노테이션은 주로 사용자가 보내온 컬렉션(배열, 리스트, 맵, 스트림) 내의 객체들을 특정 기준에 따라 필터링하고 그 중 보안 조건을 만족하는 객체들에 대해서만 메소드가 처리하도록 할때 사용된다.
```java
@PreFilter("filterObject.owner == authentication.name")
public Collection<BankAccount> updateAccounts(BankAccount[] data) {
    return data;
}

@PreFilter("filterObject.owner == authentication.name")
public Collection<BankAccount> updateAccounts(Collection<BankAccount> data) {
  return data;
}

@PreFilter("filterObject.owner == authentication.name")
public Collection<BankAccount> updateAccounts(Map<String, BankAccount> data) {
  return data;
}

@PreFilter("filterObject.owner == authentication.name")
public Collection<BankAccount> updateAccounts(Stream<BankAccount> data) {
  return data;
}
```

* @PostFilter
  * @PostFilter 애노테이션은 메소드가 반환하는 컬렉션 타입의 결과에 대해 필터링을 수행하는데 사용된다.
  * @PostFilter 애노테잇연은 메소드가 컬렉션을 반환할 때 반환되는 각 객체가 특정 보안 조건을 충족하는지 확인하고 조건을 만족하지 않는 객체들을 결과에서 제거한다.
```java
@PostFilter("filterObject.owner == authentication.name")
public List<BankAccount> readAccounts1() {
    return dataService.readList();
}

@PostFilter("filterObject.owner == authentication.name")
public Map<String, BankAccount> readAccounts2() {
  return dataService.readMap();
}
```

#### 메서드 기반 권한 부여 - @Secured, JSR-250
* @Secured
  * @Secured 애노테이션을 메소드에 적용하면 지정된 권한(역할)을 가진 사용자만 해당 메소드를 호출할 수 있으며 더 풍부한 형식을 지원하는 @PreAuthorize 사용을 권한다.
  * @Secured 애노테이션을 사용하려면 스프링 시큐리티 설정에 @EnableMethodSecurity(securedEnable = true) 설정을 활성화 해야한다.
  
```java
@Secured("ROLE_USER")
public void performUserOperation() {
    // ROLE_USER 권한을 가진 사용자만 이 메소드를 실행할 수 있습니다.
}
```

* JSR-250
  * JSR-250 기능을 적용하려면 @RolesAllowd, @PermitAll 및 @DenyAll 애노테이션 보안 기능이 활성화 된다.
  * JSR-250 애노테이션을 사용하려면 스프링 시큐리티 설정에서 @EnableMethodSecurity(jsr250Enable = true) 설정을 활성화 해야 한다.
```java
@RolesAllowed("ROLE_USER")
public void editDocument() {
    // ROLE_USER 권한을 가진 사용자만 문서를 편집할 수 있습니다.
}

@PermitAll
public void viewDocument() {
    // 모든 사용자가 문서를 볼 수 있습니다.
}

@DenyAll
public void hiddenMethod() {
    // 어떠한 사용자에게도 접근이 허용되지 않습니다.
}
```

* 메타 주석 사용
  * 메서드 보안은 애플리케이션의 특정 사용을 위해 편리성과 가독성을 높일 수 있는 메타 주석을 지원한다.

```java
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@PreAuthorize("hasRole('ADMIN')")
public @interface isAdmin() {}


@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@PostAuthorize("returnObject.owner == authentication.name")
public @interface RequireOwnerShip() {}
```
@PreAuthorize("hasRole('ADMIN'))를 다음과 같이 @IsAdmin으로 간소화할 수 있다.
```java
@IsAdmin
public BankAccount readAccount(Long id) {
    // ADMIN 권한을 가진 사용자에게 메소드 호출이 승인 될 수 있다.
}

@RequireOwnerShip
public Account readAccount(Long id) {
    // Account가 로그인한 사용자에게 속할 경우에만 반환된다.
}
```

* 특정 주석 활성화

```java
@EnableMethodSecurity(prePostEnable = false)
class MethodSecurityConfig {
    @Bean
    @Role(BeanDefinition.ROLE_INFASTRUCTURE)
    Advisor postAuthorize() {
        return AuthorizationManagerBeforeMethodInterceptor.postAuthorize();
    }
}
```
Method Security의 사전 구성을 비활성화한 다음 @PostAuthorize를 활성화 한다.

* 커스텀 빈을 사용하여 표현식 구현하기
```java
@GetMapping("/delete")
@PreAuthorize("@authorizer.isUser(#root)") // 빈 이름을 참조하고 접근 제어 로직을 수행한다.
public void delete() {
    System.out.printlnt("delete");
}

@Component("authorizer")
class MyAuthorizer {
    public boolean isUser(MethodSecurityExpressionOperations root) {
        boolean decision = root.hasAuthority("ROLE_USER"); // 인증된 사용자가 ROLE_USER 권한을 가지고 있는지 검사
        return decision;
    }
}
```

* 클래스 레벨 권한 부여
```java
@Controller
@PreAuthorize("hasAuthority('ROLE_USER')")
public class MyController { 
    @GetMapping("/endPoint")
    public String endPoint() {
      ...
    }
}
```
* 모든 메소드는 클래스 수준의 권한 처리 동작을 상속한다.

```java
@Controller
@PreAuthorize("hasAuthority('ROLE_USER')")
public class MyController { 
    @GetMapping("/endPoint")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')") // 이 설정이 우선적으로 동작한다.
    public String endPoint() {
      ...
    }
}
```
* 메서드에 애노테이션을 선언한 메소드는 클래스 수준의 애노테이션을 덮어 쓰게 된다.
* 인터페이스에도 동일한 규칙이 적용되지만 클래스가 두 개의 다른 인터페이스로부터 동일한 메서드의 애노테이션을 상속 받는 경우에는 시작할 때 실패한다. 그래서 구체적인 애노테이션을 추가함으로써 모호성을 해결할 수 있다.

### 정적 자원 관리
* 스프링 시큐리티에서는 RequestMatcher 인스턴스를 등록하여 무시해야할 요청을 지정할 수 있다.
* 주로 정적자원(이미지, CSS, JavaScript 파일 등)에 대한 요청이나 특정 엔드포인트가 보안 필터를 거치지 않도록 설정할 때 사용된다.
```java
@Bean
public WebSecurityCustomizer webSecurityCustomizer() {
    return (webSecurity) -> {
        webSecurity.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    };
}
```
```java
public enum StaticResourceLocation {
  CSS(new String[]{"/css/**"}),
  JAVA_SCRIPT(new String[]{"/js/**"}),
  IMAGES(new String[]{"/images/**"}),
  WEB_JARS(new String[]{"/webjars/**"}),
  FAVICON(new String[]{"/favicon.*", "/*/icon-*"});

  private final String[] patterns;

  private StaticResourceLocation(String... patterns) {
    this.patterns = patterns;
  }

  public Stream<String> getPatterns() {
    return Arrays.stream(this.patterns);
  }
}
```
* Ignoring 보다 permitAll 권장
```java
http.authorizeHttpRequests(auth -> auth
        .requestMatchers("/css/**", "/js/**", "/images/**", "/webjars/**", "/favicon.*", "/*/icon-*").permitAll()
        .requestMatchers(PathRequest.toStaticResources().atCommonLocations()).permitAll()
        .anyRequest().authenticated();
)
```
* 이전에는 모든 요청마다 세션을 확인해야 해서 성능 저하가 있었지만 스프링 시큐리티 6부터는 권한 부여 규칙에서 필요한 경우를 제외하고는 세션을 확인하지 않는다.
* 성능 문제가 해결되었기 때문에 모든 요청에 대해서 permitAll을 사용할 것을 권장하며 정적 자원에 대한 요청일지라도 안전한 헤더를 작성할 수 있어 더 안전하다.

### 계층적 권한
* 기본적으로 스프링 시큐리티에서 권한과 역할은 계층적이거나 상하 관계로 구분하지 않는다. 그래서 인증 주체가 다양한 역할과 권한을 부여 받아야 한다.
* RoleHierarchy는 역할 간의 계층 구조를 정의하고 관리하는 데 사용되며 보다 간편하게 역할 간의 계층 구조를 설정하고 이를 기반으로 사용자에 대한 엑세스 규칙을 정의할 수 있다.
```xml
<property name="hierachy">
  <value>
    ROLE_A > ROLE_B
    ROLE_B > ROLE_C
    ROLE_C > ROLE_D
  </value>
</property>
```
* ROLE_A를 가진 모든 사용자는 ROLE_B, ROLE_C, ROLE_D도 가지게 된다.
* ROLE_B를 가진 모든 사용자는 ROLE_C, ROLE_D도 가지게 된다.
* ROLE_C를 가진 모든 사용자는 ROLE_D도 가지게 된다.
* 계층적 역할을 사용하면 엑세스 규칙이 크게 줄어들 뿐만 아니라 더 간결하고 우아한 형태로 규칙을 표현할 수 있다.

* 구조
```java
public interface RoleHierarchy {
    Collection<? extends GrantedAuthority> getReachableGrantedAuthorities(Collection<? extends GrantedAuthority> authorities);
}
```
```java
public class RoleHierarchyImpl implements RoleHierarchy {
  public Collection<GrantedAuthority> getReachableGrantedAuthorities(Collection<? extends GrantedAuthority> authorities);
  private static Map<String, Set<GrantedAuthority>> buildRolesReachableInOneStepMap(String hierarchy);
  public void setHierarchy(String roleHierarchyStringRepresentation);
  private static Map<String, Set<GrantedAuthority>> buildRolesReachableInOneOrMoreStepsMap(Map<String, Set<GrantedAuthority>> hierarchy);
}
```
```java
@Bean
static RoleHierarchy roleHierarchy() {
    RoleHierarchyImpl hierarchy = new RoleHierarchyImpl();
    hierarchy.setHierarchy(
            "ROLE_ADMIN > ROLE_MANAGER\n"
            + "ROLE_MANAGER > ROLE_USER\n"
            + "ROLE_USER > ROLD_GUEST"
    );
    return hierarchy;
}
```
* setHierarchy
  * 역할 계층을 설정하고 각 역할에 대해 해당 역할의 하위 계층에 속하는 모든 역할 집합을 미리 정해 놓는다.
    * 역할 계층 ROLE_A > ROLE_B > ROLE_C 
* getReachableGrantedAuthorities
  * 모든 도달 가능한 권한의 배열을 반환한다.
  * 도달 가능한 권한은 직접 할당된 권한에 더해 역할 계층에서 이들로부터 도달 가능한 모든 권한을 의미한다.
    * 직접 할당 권한: ROLE_B
    * 도달 가능한 권한: ROLE_B, ROLE_C

---
## 인가 아키텍처
### 인가 - Authorization
* 인가 즉 권한 부여는 특정 자원에 접근할 수 있는 사람을 결정하는 것을 의미한다.
* SpringSecurity는 GrantedAuthority 클래스를 통해 권한 목록을 관리하고 있으며 사용자의 Authentication 객체와 연결한다.

#### GrantedAuthority
* 스프링 시큐리티는 Authentication에 GrantedAuthority 권한 목록을 저장하며 이를 통해 인증 주체에게 부여된 권한을 사용하도록 한다.
* GrantedAuthority 객체는 AuthenticationManager에 의해 Authentication 객체에 삽입되며 스프링 시큐리티는 인가 결정을 내릴 때 AuthorizationManager를 사용하여 Authentication 즉, 인증 주체로부터 GrantedAuthority 객체를 읽어들여 처리하게 된다.

#### 구조
```java
public interface GrantedAuthority extends Serializable {
    String getAuthority();
}
```
```java
public final class SimpleGrantedAuthority implements GrantedAuthority {
    private static final long serialVersionUID = 620L;
    private final String role;

    public SimpleGrantedAuthority(String role) {
        Assert.hasText(role, "A granted authority textual representation is required");
        this.role = role;
    }

    public String getAuthority() {
        return this.role;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        } else if (obj instanceof SimpleGrantedAuthority) {
            SimpleGrantedAuthority sga = (SimpleGrantedAuthority)obj;
            return this.role.equals(sga.getAuthority());
        } else {
            return false;
        }
    }

    public int hashCode() {
        return this.role.hashCode();
    }

    public String toString() {
        return this.role;
    }
}
```
* getAuthority(): AuthorizationManager가 GrantedAuthority의 정확한 문자열 표현을 얻기 위해 사용 된다.

#### 사용자 정의 역할 접두사
* 기본적으로 역할 기반의 인가 규칙은 역할 앞에 `ROLE_`를 접두사로 사용한다. 즉 `USER` 역할을 가진 보안 컨텍스트가 필요한 인가 규칙이 있으면 SpringSecurity는 기본적으로 `ROLE_USER`를 반환하는 GrantedAuthority.getAuthority를 찾는다.
* GrantedAuthorityDefaults는 사용자 지정할 수 있으며, GrantedAuthorityDefaults는 역할 기반 인가 규칙에 사용할 접두사를 사용자 정의하는데 사용 사용된다.

### 인가 관리자 이해 - AuthorizationManager
* AuthorizationManager는 인증된 사용자가 요청자원에 접근할 수 있는지 여부를 결정하는 인터페이스로서 인증된 사용자의 권한 정보와 요청 자원의 보안 요구사항을 기반으로 권한 부여 결정을 내린다.
* AuthorizationManager는 SpringSecurity의 요청 기반, 메서드 기반의 인가 구성 요소에서 호출되며 최종 액세스 제어 결정을 수행한다.
* AuthorizationManager는 SpringSecurity의 필수 구성요소로서 권한 부여 처리는 AuthorizationFilter를 통해 이루어지며 AuthorizationFilter는 AuthorizationManager를 호출하여 권한 부여 걸정을 내린다.

#### 구조
```java
@FunctionalInterface
public interface AuthorizationManager<T> {
    default void verify(Supplier<Authentication> authentication, T object) {
        AuthorizationDecision decision = this.check(authentication, object);
        if (decision != null && !decision.isGranted()) {
            throw new AccessDeniedException("Access Denied");
        }
    }

    @Nullable
    AuthorizationDecision check(Supplier<Authentication> authentication, T object);
}
```
* verify()
  * check를 호출해서 반환된 값이 false를 가진 AuthorizationDecision 인 경우 AccessDeniedException을 throw 한다.
* check(): 
  * 권한 부여 걸정을 내릴 때 필요한 모든 관련 정보(인증객체, 체크 대상(권한정보, 요청정보, 호출정보 등..))가 전달된다.
  * 액세스가 허용되면 true를 포함하는 AuthorizationDecision, 거부되면 false를 포함하는 AuthorizationDecision, 결정을 내릴 수 없는 경우 null을 반환한다.

#### AuthorizationManager 클래스 계층 구조
* AuthorizationManager
  * RequestMatcherDelegatingAuthorizationManager(요청 기반 권한 부여 관리자)
    * AuthenticatedAuthorizationManager
    * AuthorityAuthorizationManager
    * WebExpressionAuthorizationManager
  * PreAuthorizeAuthorizationManager(메서드 기반 권한 부여 관리자)
  * PostAuthorizeAuthorizationManager(메서드 기반 권한 부여 관리자)
  * Jsr250AuthorizationManager(메서드 기반 권한 부여 관리자)
  * SecuredAuthorizationManager(메서드 기반 권한 부여 관리자)

#### AuthorizationManager 구현체 종류 및 특징
* AuthorityAuthorizationManager
  * 특정 권한을 가진 사용자에게만 접근을 허용한다. 주로 사용자의 권한(예: ROLE_USER, ROLE_ADMIN)을 기반으로 접근을 제어한다.
* AuthenticationAuthorizationManager
  * 인증된 사용자에게 접근을 허용한다. 이 클래스는 사용자가 시스템에 로그인했는지 여부를 기준으로 결정한다.
* WebExpressionAuthorizationManager
  * 웹 보안 표현식을 사용하여 권한을 관리한다. 예를 들어, `hasRole('ADMIN')` 또는 `hasAuthority('WRITE_PERMISSIONS')`와 같은 표현식을 사용할 수 있다.
* RequestMatcherDelegatingAuthorizationManager
  * 인가설정에서 지정한 모든 요청패턴과 권한 규칙을 매핑한 정보를 가지고 있으며 권한 검사 시 가장 적합한 AuthorizationManager 구현체를 선택해 위임한다.
* PreAuthorizeAuthorizationManager
  * 메소드 실행 전에 권한을 검사한다. @PreAuthorize 애너테이션과 함께 사용되며, 메소드 실행 전에 사용자의 권한을 확인한다.
* PostAuthorizeAuthorizationManager
  * 메소드 실행 후에 권한을 검사한다. @PostAuthorize 애너테이션과 함께 사용되며, 메소드 실행 후 결과에 따라 접근을 허용하거나 거부한다.
* Jsr250AuthorizationManager
  * JSR-250 애너테이션(@RolesAllowed, @DenyAll, @PermitAll)을 사용하여 권한을 관리한다.
* SecuredAuthorizationManager
  * @Secured 애너테이션을 사용하여 메소드 수준의 보안을 제공한다. 이 애너테이션은 특정 권한을 가진 사용자만 메소드에 접근할 수 있게 한다.

### 요청 기반 인가 관리자 - AuthorityAuthorizationManager
* 스프링 시큐리티는 요청 기반의 인증된 사용자 및 특정 권한을 가진 사용자의 자원접근 허용여부를 결정하는 인가 관리자 클래스들을 제공한다.
* 대표적으로 AuthorityAuthorizationManager, AuthenticationAuthorizationManager와 대리자인 RequestMatcherDelegatingAuthorizationManager가 있다.

### 요청 기반 Custom AuthorizationManager 구현
* 스프링 시큐리티 인가 설정 시 선언적 방식이 아닌 프로그래밍 방식으로 구현할 수 있으며 access(AuthorizationManager) API를 사용한다.
* access()에는 AuthorizationManager<RequestAuthorizationContext> 타입의 객체를 전달할 수 있으며 사용자의 요청에 대한 권한 검사를 access()에 지정한 AuthorizationManager가 처리하게 된다.
* accesss()에 지정한 AuthorizationManager 객체는 RequestMatcherDelegatingAuthorizationManager의 매핑 속성에 저장된다.
```java
http.authorizeHttpRequests(auth -> auth.requestMatcher().access(AuthorizationManager))
```
#### 적용
* 특정 엔드포인트에 대한 권한 검사를 수행하기 위해 AuthorizationManager를 구현하여 설정한다.
```java
http.authorizeHttpRequests(auth -> auth
    .requestMatchers("/user", "/myPage").hasAuthority("USER")
    .requestMatchers("/admin").hasRole("ADMIN")
    .requestMatchers("/api").access(new CustomAuthorizationManager())
);
```
* `/user`, `/myPage`, `/admin` 요청 패턴의 권한 검사는 AuthorityAuthorizationManager가 처리한다.
* `/api`, 요청 패턴의 권한 검사는 CustomAuthorizationManager가 처리한다.

#### CustomAuthorizationManager

```java
import java.util.function.Supplier;

public class CustomAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {
  private static final String REQUIRED_ROLE = "ROLE_SECURE";

  @Override
  public AuthorizationDecision check(Supplier<Authentication> authentication, RequestAuthorizationContext object) {
      Authentication auth = authentication.get();
      
      // 인증 정보가 없거나 인증 되지 않은 경우
      if (auth == null || !auth.isAuthenticated() || auth instanceof AnonymousAuthenticationToken) {
          return new AuthorizationDecision(false);
      }
      
      boolean hasRequiredRole = auth.getAuthorities().stream()
              .anyMatch(grantedAuthority -> REQUIRED_ROLE.equals(grantedAuthority.getAuthority()));
      
      return new AuthorizationDecision(hasRequiredRole);
  }
}
```

### RequestMatcherDelegatingAuthorizationManager로 인가 설정 응용하기
* RequestMatcherDelegatingAuthorizationManager의 mapping 속성에 직접 RequestMatcherEntry 객체를 생성하고 추가한다.
```java
public class RequestMatcherEntry<T> {
    private final RequestMatcher requestMatcher;
    private final T entry;

    public RequestMatcherEntry(RequestMatcher requestMatcher, T entry) {
        this.requestMatcher = requestMatcher;
        this.entry = entry;
    }

    public RequestMatcher getRequestMatcher() {
        return this.requestMatcher;
    }

    public T getEntry() {
        return this.entry;
    }
}
```
* getRequestMatcher(): 요청 패턴을 저장한 RequestMatcher 객체를 반환한다.
* getEntry(): AuthorizationManager 객체를 반환한다.

```java
List<RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>>> mappings = new ArrayList<>();

RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>> requestMatcherEntry = 
    new RequestMatcherEntry<>(new MvcRequestMatcher(introspector, "/user"), AuthorityAthorizationManager.hasAuthority("ROLE_USER"));

mappings.add(requestMatcherEntry);
```

```java
RequestMatcherDelegatingAuthorizationManager.builder().mappings(maps -> maps.addAll(mappings)).build();
```
#### 적용
* RequestMatcherDelegatingAuthorizationManager를 감싸는 CustomRequestMatcherDelegatingAuthorizationManager를 구현한다.
```java
http.authorizeHttpRequest(auth -> auth.anyRequest().access(new CustomRequestMatcherDelegatingAuthorizationManager()));
```

#### SecurityConfig.java
```java
@Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http.authorizeHttpRequests(auth -> auth.anyRequest().access(authorizationManager(null))).build();
    }

    @Bean
    public AuthorizationManager<RequestAuthorizationContext> authorizationManager(HandlerMappingIntrospector introspector) {
        List<RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>>> mappings = new ArrayList<>();

        RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>> entry0 =
                new RequestMatcherEntry<>(new MvcRequestMatcher(introspector, "/user"), AuthorityAuthorizationManager.hasAuthority("ROLE_USER"));

        RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>> entry1 =
                new RequestMatcherEntry<>(new MvcRequestMatcher(introspector, "/admin"), AuthorityAuthorizationManager.hasRole("ADMIN"));

        RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>> entry2 =
                new RequestMatcherEntry<>(AnyRequestMatcher.INSTANCE, new AuthenticatedAuthorizationManager<>());

        mappings.add(entry0);
        mappings.add(entry1);
        mappings.add(entry2);

        return new CustomRequestMatcherDelegatingAuthorizationManager(mappings);
    }
```

#### CustomRequestMatcherDelegatingAuthorizationManager.java
```java
public class CustomRequestMatcherDelegatingAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {

    private final RequestMatcherDelegatingAuthorizationManager manager;

    public CustomRequestMatcherDelegatingAuthorizationManager(List<RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>>> mappings) {
        Assert.notEmpty(mappings, "mappings must not be empty");
        manager = RequestMatcherDelegatingAuthorizationManager.builder().mappings(maps -> maps.addAll(mappings)).build();
    }

    @Override
    public AuthorizationDecision check(Supplier<Authentication> authentication, RequestAuthorizationContext object) {
        return manager.check(authentication, object.getRequest());
    }

    @Override
    public void verify(Supplier<Authentication> authentication, RequestAuthorizationContext object) {
        AuthorizationManager.super.verify(authentication, object);
    }
}
```
* 요청에 대한 권한 검사를 RequestMatcherDelegatingAuthorizationManager 객체가 수행하도록 한다.
* RequestMatcherDelegatingAuthorizationManager > CsutomRequestMatcherDelegatingAuthorizationManager > RequestMatcherDelegatingAuthorizatioinManager 구조는 개선이 필요하다.

## 메서드 기반 인가 관리자 - PreAuthorizeAuthorizationManager
* 스프링 시류키티는 메서드 기반의 인증된 사용자 및 특정권한을 가진 사용자의 자원접근 허용여부를 결정하는 인가 관리자 클래스들을 제공한다.
* PreAuthorizeAuthorizationManager, PostAuthorizeAuthorizationManager, Jsr250AuthorizationManager, SecuredAuthorizationManger가 있다.
* 메서드 기반 권한 부여는 내부적으로 AOP 방식에 초기화 설정이 이루어지며 메서드의 호출을 MethodInterceptor가 가로채어 처리하고 있다.

### 메서드 인가 처리
```java
@PreAuthorize("hasAuthority('ROLE_USER')")
public List<User> users() {
    System.out.println("users: " + UserRepositoriy.findAll());
}
```

### 메서드 권한 부여 초기화 과정
1. 스프링은 초기화 시 생성되는 전체 빈을 검사하면서 빈이 가진 메소드 중에서 보안이 설정된 메소드가 있는지 탐색한다.
2. 보안이 설정된 메소드가 있다면 스프링은 그 빈의 프록시 객체를 자동으로 생성한다.(기본적으로 Cglib 방식으로 생성)
3. 보안이 설정된 메소드에는 인가처리 기능을 하는 Advice를 등록한다.
4. 스프링은 빈 참조시 실제 빈이 아닌 프록시 빈 객체를 참조하도록 처리한다.
5. 초기화 과정이 종료된다.
6. 사용자는 프록시 객체를 통해 메소드를 호출하게 되고 프록시 객체는 Advice가 등록된 메서드가 있다면 호출하여 작동시킨다.
7. Advice는 메소드 진입 전 인가처리를 하게 되고 인가처리가 승인되면 실체 객체의 메소드를 호출하게 되고 인가처리가 거부되면 예외가 발생하고 메소드 진입이 실패한다.

#### 메서드 Interceptor 구조
* MethodInterceptor
  * AuthorizationManagerBeforeMethodInterceptor
    * 지정된 AuthorizationManager를 사용하여 Authentication이 보안 메서드를 호출 할 수 있는지 여부를 결정하는 MethodInterceptor 구현체
  * AuthorizationManagerAfterMethodInterceptor
    * 지정된 AuthorizationManager를 사용하여 Authentication이 보안 메서드의 반환 결과에 접근 할 수 있는지 여부를 결정할 수있는 구현체
  * PreFilterAuthorizationMethodInterceptor
    * @PreFilter 애너테이션에서 표현식을 평가하여 메소드 인자를 필터링하는 구현체
  * PostFilterAuthorizationMethodInterceptor
    * @PostFilter 애너테이션에서 표현식을 평가하여 보안 메서드에서 반환 객체를 필터링하는 구현

### 메서드 기반 Custom AuthorizationManager 구현
* 사요자 정의 AuthorizationManager를 생성함으로 메서드 보안을 구현할 수 있다.

#### 설정 클래스 정의
```java
@Configuration
@EnableMethodSecurity(prePostEnabled = false) // 시큐리티가 제공하는 클래스들을 비활성화 한다. 그렇지 않으면 중복해서 검사하게 된다.
public class MethodSecurityConfig {

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    public Advisor preAuthorize() {
        return AuthorizationManagerBeforeMethodInterceptor.preAuthorize(new MyPreAuthorizationManager());
    }

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    public Advisor postAuthorize() {
        return AuthorizationManagerAfterMethodInterceptor.postAuthorize(new MyPostAuthorizationManager());
    }
}
``` 

#### 사용자 정의 AuthorizationManager 구현
```java
public class MyPreAuthorizationManager implements AuthorizationManager<MethodInvocation> {

    @Override
    public AuthorizationDecision check(Supplier<Authentication> authentication, MethodInvocation object) {
        return new AuthorizationDecision(authentication.get().isAuthenticated());
    }
}
```
```java
public class MyPostAuthorizationManager implements AuthorizationManager<MethodInvocationResult> {

    @Override
    public AuthorizationDecision check(Supplier<Authentication> authentication, MethodInvocationResult object) {
        Authentication auth = authentication.get();

        if (auth instanceof AnonymousAuthenticationToken) return  new AuthorizationDecision(false);

        Account account = (Account) object.getResult();

        boolean isGranted = account.getOwner().equals(authentication.get().getName());

        return new AuthorizationDecision(isGranted);
    }
}
```
* 사용자 정의 AuthorizationManager는 여러 개 추가할 수 있으며 그럴 경우 체인 형태로 연결되어 각각 권한 검사를 하게 된다.

#### 인터셉터 순서 지정
```java
package org.springframework.security.authorization.method;

public enum AuthorizationInterceptorsOrder {
    FIRST(Integer.MIN_VALUE),
    PRE_FILTER,
    PRE_AUTHORIZE,
    SECURED,
    JSR250,
    SECURE_RESULT(450),         
    POST_AUTHORIZE(500),        
    POST_FILTER(600),
    LAST(Integer.MAX_VALUE);

    private static final int INTERVAL = 100;
    private final int order;

    private AuthorizationInterceptorsOrder() {
        this.order = this.ordinal() * 100;
    }

    private AuthorizationInterceptorsOrder(int order) {
        this.order = order;
    }

    public int getOrder() {
        return this.order;
    }
}
```
* 메서드 보안 애너테이션에 대응하는 AOP 메소드 인터셉터들은 AOP 어드바이저 체인에서 특정 위치를 차지한다.
* 구체적으로 `@PreFilter` 메소드 인터셉터의 순서는 100, `@PreAuthorize`의 순서는 200 등으로 설정 되어있다.
* 이것이 중요한 이유는 `@EnableTransactionManagement`와 같은 다른 AOP 기반 애너테이션들이 `Integer.MAX_VALUE`로 순서가 설정되어있는데 기본적으로 이들은 어드바이저 체인의 끝에 위치하고 있다.
* 만약 스프링 시큐리티보다 먼저 다른 어드바이스가 실행 되어야 할 경우, 예를 들어 `@Transactional`과 `@PostAuthorize`가 함께 애너테이션 된 메소드가 있을 때 `@PostAuthorize`가 실행될 때 트랜잭션이 여전히 열려있어서 AccessDeniedException이 발생하면 롤백이 일어나게 하고 싶을 수 있다.
* 그래서 메소드 인가 어드바이스가 실행되기 전에 트랜잭션을 열기 위해서는 `@EnableTransactionManagement`의 순서를 설정해야 한다.
* `@EnableTransactionManagement(order = 0)`
  * 위의 order = 0 설정은 트랜잭션 관리가 `@PreFilter` 이전에 실행되도록 하며 `@Transactional` 애너테잉션이 적용된 메소드가 스프링 시큐리티의 `@PostAuthorize`와 같은 보안 애너테이션보다 먼저 실해오디어 트랜잭션이 열린 상태에서 보안 검사가 이루어지도록 할 수 있다. 
    이러한 설정은 트랜잭션 관리와 보안 검사의 순서에 따른 의도하지 않은 사이드 이펙트를 방지할 수 있다.
* AuthorizationInterceptorsOrder를 사용하여 인터셉터 간 순서를 지정할 수 있다.
