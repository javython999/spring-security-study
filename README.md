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