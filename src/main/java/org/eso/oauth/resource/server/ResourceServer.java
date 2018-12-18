package org.eso.oauth.resource.server;

import java.security.Principal;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.jwk.JwkTokenStore;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@RestController
@EnableGlobalMethodSecurity(prePostEnabled = true)
@EnableResourceServer
public class ResourceServer  extends ResourceServerConfigurerAdapter {
	
	@Value("${security.oauth2.resource.jwk.key-set-uri}") 
	private String jwksUrl;
	
	@Value("${jwt.reourceId:clientid}")
	private String resourceId;

    public static void main(String[] args) {
        SpringApplication.run(ResourceServer.class, args);
    }

    @RequestMapping(value = "/user", method = RequestMethod.GET)
    public Object user(Principal user) {
    	Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    	return auth;
    }
    @Bean
  public DefaultTokenServices tokenServices(final TokenStore tokenStore) {
    final DefaultTokenServices dts = new DefaultTokenServices();
    dts.setTokenStore(tokenStore);
    dts.setSupportRefreshToken(true);
    return dts;
  }

  @Bean
  @Primary
  public TokenStore tokenStore() {
	  return new JwkTokenStore(jwksUrl, createJwtAccessTokenConverter());
  }
  
  @Bean
  public JwtAccessTokenConverter createJwtAccessTokenConverter() {
    final JwtAccessTokenConverter converter = new JwtAccessTokenConverter();   
    converter.setAccessTokenConverter(new  DefaultAccessTokenConverter() {
      @Override
      public OAuth2Authentication extractAuthentication(Map<String, ?> map) {
        final OAuth2Authentication auth = super.extractAuthentication(map);
        auth.setDetails(map); //this will get spring to copy JWT content into 
        return auth;
        }

      });
    return converter;
  }
   
    /**
    * Configure resources
    * Spring OAuth expects "aud" claim in JWT token. That claim's value should match to the resourceId value
    * (if not specified it defaults to "oauth2-resource").
    */
     @Override 
     public void configure(final ResourceServerSecurityConfigurer resources) {
       resources.resourceId(resourceId).tokenStore(tokenStore());
     }

}
