package com.tech.mkblogs.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

import com.tech.mkblogs.security.config.AccountAuthConfig;
import com.tech.mkblogs.security.db.DBAuthProvider;
import com.tech.mkblogs.security.inmemory.InMemoryAccountUserDetails;

@Configuration
@EnableWebSecurity      
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	
	@Autowired
	private AccountAuthConfig authConfig;
	
	@Autowired
	private InMemoryAccountUserDetails inmemoryDetails;
   
	@Autowired
	private DBAuthProvider dbAuthProvider;
	
   	
  // Securing the urls and allowing role-based access to these urls.
  @Override
  protected void configure(HttpSecurity http) throws Exception {
      http.authorizeRequests()
      .antMatchers("/admin").hasRole("ADMIN")
      .antMatchers("/user").hasAnyRole("USER","ADMIN")
      .antMatchers("/").permitAll()
      .and().csrf().disable();
      
      http.formLogin();
     // http.logout().invalidateHttpSession(true);
  }

  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	  switch (authConfig.getAuthType().toLowerCase()) {
	  	case "inmemory":
	  		try {
	  			inmemoryDetails.configureInMemoryUserVerification(auth);
			}catch(Exception e) {
				e.printStackTrace();
				throw new RuntimeException("Exception while in-memory method ::"+e.getMessage());
			}
	  	break;
	  	case "db":
	  		try {
	  			auth.authenticationProvider(dbAuthProvider);
			}catch(Exception e) {
				e.printStackTrace();
				throw new RuntimeException("Exception while in-memory method ::"+e.getMessage());
			}
	  	break;	
	  	default:
	  		try {
	  			inmemoryDetails.configureInMemoryUserVerification(auth);
			}catch(Exception e) {
				e.printStackTrace();
				throw new RuntimeException("Exception while in-memory method in default case ::"+e.getMessage());
			}
		break;
	  }
  }
  
  
 
  
  
}
