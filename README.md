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