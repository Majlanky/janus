# Janus
[![Build Status](https://travis-ci.com/Majlanky/janus.svg?branch=master)](https://travis-ci.com/Majlanky/janus)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=com.groocraft%3Ajanus&metric=coverage)](https://sonarcloud.io/dashboard?id=com.groocraft%3Ajanus)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=com.groocraft%3Ajanus&metric=sqale_rating)](https://sonarcloud.io/dashboard?id=com.groocraft%3Ajanus)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=com.groocraft%3Ajanus&metric=security_rating)](https://sonarcloud.io/dashboard?id=com.groocraft%3Ajanus)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=com.groocraft%3Ajanus&metric=reliability_rating)](https://sonarcloud.io/dashboard?id=com.groocraft%3Ajanus)
[![Known Vulnerabilities](https://snyk.io/test/github/majlanky/janus/badge.svg)](https://snyk.io/test/github/majlanky/janus)  
![](https://img.shields.io/badge/compatibility-JDK8%20and%20higher-purple)
![](https://img.shields.io/badge/Servlet%20security-ready-brightgreen)
![](https://img.shields.io/badge/Reactive%20security-ready-brightgreen)


Is spring multitenant OAuth2 resource server library. When spring resource server is used there is the possibility to configure one 
IdP. What if we need more IdP? There are some use cases from rewriting obsolete app to simple application which should work with more IdPs 
like Google, Facebook etc. without necessity to run Keycloak or similar SW in provider mode. Janus is the answer. With Janus, we can
easily replace standard resource server, keep current configuration as is and simply add new IdPs.

Artifacts releases are available on maven central (and on pages indexing central):
* [central](https://repo1.maven.org/maven2/com/groocraft/janus/)
* [mvnRepository](https://mvnrepository.com/artifact/com.groocraft/janus)

## Wiki
This README contains only basic information about project. For more or detailed information, visit the [wiki](https://github.com/Majlanky/janus/wiki)

## Limitations and coming soon
Janus does not support reactive stack right now. But it is planned to the next release to support it.

## How to start
First things first we have to add Maven dependency
```xml
<dependency>
    <groupId>com.groocraft</groupId>
    <artifactId>janus</artifactId>
  <version>${version}</version>
</dependency>
```
You will need the original spring resource server library. If you do not have it added yet, add it:
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
  <version>${version}</version>
</dependency>
```

## Configuration
There are two configuration needed. One is the configuration of IdPs, the other is configuration of web security with Janus.

![](https://img.shields.io/badge/-Warning-red)  
In both cases you must use @EnableJanus or @EnableReactiveJanus if you do not have auto-configuration turned on.

### Configuration of IdPs:
As you can see the structure of resource server remains the same, but we can add more named IdPs:
```yaml
spring:
  security:
    oauth2:
      resourceserver:
        first:
          issuer-uri: ...
          jwk-set-uri: ...
        second:
          issuer-uri: ...
          jwk-set-uri: ...
          roles-claim-name: realm_roles
          roles-authority-prefix: REALM_ROLE
        third:
          jws-algorithm: PS512
          public-key-location: 'classpath:key.pub'
```
As you can see the configuration for IdPs supports JWK and local approach, all algorithms and customization of JWT parsing/translation to
Authentication object.

### Configuration of servlet based web security

There are more ways how to configure web security. WebSecurityAdapterConfigurer was standard for a long time, SecurityFilterChain is the 
new approach. The following provides examples how use Janus with both of them where we prefer the newer one.

##### SecurityFilterChain approach
```java
public class WebSecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, WithMultiIdPsCustomizer withMultiIdPs) {
        return http.authorizeRequests().anyRequest().fullyAuthenticated().and()
            .httpBasic().disable()
            .formLogin().disable()
            .csrf().disable()
            .cors(Customizer.withDefaults())
            .oauth2ResourceServer(withMultiIdPs)
            .sessionManagement(c -> c
                .sessionAuthenticationStrategy(new NullAuthenticatedSessionStrategy())
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)).build();
    }
}
```

##### WebSecurityConfigurerAdapter approach
```java
public class WebSecurityConfig extends JanusWebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) {
        http.authorizeRequests().anyRequest().fullyAuthenticated().and()
            .httpBasic().disable()
            .formLogin().disable()
            .oauth2ResourceServer(withMultiIdPs())
            .cors(Customizer.withDefaults())
            .sessionManagement(c -> c
                .sessionAuthenticationStrategy(new NullAuthenticatedSessionStrategy())
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS));
    }
}
```

### Configuration of servlet based web security ![](https://img.shields.io/badge/From%20version-1.1.0-green)

With reactive security there is only one way to configured it, and it is very similar to the first way at the previous chapter:

```java
public class WebSecurityConfig {

    @Bean
    public SecurityWebFilterChain securityFilterChain(ServerHttpSecurity http, ReactiveWithMultiIdPsCustomizer withMultiIdPs) {
        return http.authorizeExchange().anyExchange().authenticated().and()
                .httpBasic().disable()
                .formLogin().disable()
                .csrf().disable()
                .cors(Customizer.withDefaults())
                .oauth2ResourceServer(withMultiIdPs).build();
    }
}
```


## Testing with Janus
Testing with Janus should be smooth if you use full scope context with @SpringBootTest for example. If you are using @WebMvcTest you will
need to add Janus manually as it will not be automatically enabled. For manual enabling, using @EnableJanus or @EnableReactiveJanus annotation.
