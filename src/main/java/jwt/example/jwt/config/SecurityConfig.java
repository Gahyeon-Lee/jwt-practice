package jwt.example.jwt.config;

import jwt.example.jwt.jwt.JwtAuthenticationFilter;
import jwt.example.jwt.jwt.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@RequiredArgsConstructor
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final JwtTokenProvider jwtTokenProvider;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .httpBasic().disable() // rest api만을 고려해서 기본 설정 해제
                .csrf().disable() // csrf 보안 토큰 disable 처리
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 토큰 기반 인증이므로 세션 또한 사용하지 않음
                .and()
                .authorizeRequests() // 요청에 대한 사용권한 체크
                .antMatchers("/admin/**").hasRole("ADMIN") // "/admin/**" 형식의 URL로 들어오는 요청에 대한 인증
                .antMatchers("/user/**").hasRole("USER")   // "/user/**"  형식의 URL로 들어오는 요청에 대한 인증
                .anyRequest().permitAll() // 그 외 나머지 요청은 누구나 접근 가능하게
                .and()
                .addFilterBefore(new JwtAuthenticationFilter(jwtTokenProvider),
                        UsernamePasswordAuthenticationFilter.class);
        // JwtAuthenticationFilter를 UsernamePasswordAuthenticationFilter 전에 넣어준다.
    }
}
