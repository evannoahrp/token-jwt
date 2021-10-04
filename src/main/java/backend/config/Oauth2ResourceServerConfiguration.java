package backend.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;

@Configuration
@EnableResourceServer
public class Oauth2ResourceServerConfiguration extends ResourceServerConfigurerAdapter {

    /**
     * Manage resource server.
     */
    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
        super.configure(resources);
    }

    private static final String SECURED_PATTERN = "/api/**";

    /**
     * Manage endpoints.
     */
    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.cors()
                .and()
                .csrf()
                .disable()
                .antMatcher("/**")
                .authorizeRequests()
                .antMatchers("/", "/ar/**", "/oauth/authorize**", "/login**", "/error**")
                .permitAll()
                .and()
                .authorizeRequests()
                .anyRequest()
                .authenticated()
                .and()
                .formLogin()
                .permitAll()
        ;

//        http.cors()
//                .and()
//                .csrf()
//                .disable()
//                .antMatcher("/**")
//                .authorizeRequests()
//                    .antMatchers("/",  "/oauth/authorize**", "/ar/**", "/api/ar/**", "/login**", "/error**")
//                    .permitAll()
//                .and()
//                .authorizeRequests()
//                    .anyRequest()
//                    .authenticated()
////                .and()
////                    .formLogin()
////                    .permitAll()
//        ;


//        http.requestMatchers()
//                .antMatchers("/api/v1/**")
//                .and()
//                .authorizeRequests()
//                    .antMatchers("/api/v1/**", "/oauth/authorize**", "/login**", "/error**")
//                    .permitAll()
//                .and()
//                .authorizeRequests()
//                    .anyRequest()
//                    .authenticated()
//                .and()
//                    .formLogin()
//                    .permitAll()
//        ;
    }
}
