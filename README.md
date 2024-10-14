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