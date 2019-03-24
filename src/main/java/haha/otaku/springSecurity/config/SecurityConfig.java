package haha.otaku.springSecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import haha.otaku.springSecurity.security.CustomAccessDeniedHandler;
import haha.otaku.springSecurity.security.CustomAuthenticationFailHandler;
import haha.otaku.springSecurity.security.CustomLogoutHandler;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	/**
	 * 配置用户认证
	 */
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		//在内存中创建相关用户，配置相应的角色
		auth.inMemoryAuthentication()
			.withUser("user1").password(passwordEncoder().encode("user1Pass")).roles("USER")
			.and()
			.withUser("user2").password(passwordEncoder().encode("user2Pass")).roles("USER")
			.and()
			.withUser("admin").password(passwordEncoder().encode("adminPass")).roles("ADMIN");
	}

	/**
	 * 配置http相关安全特性
	 */
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.csrf().disable()
			.authorizeRequests()
				.antMatchers("/admin/**").hasRole("ADMIN") // /admin开头的url需要ADMIN角色才能访问
				.antMatchers("/anonymous*").anonymous() // 未登录用户可访问
				.antMatchers("/login*").permitAll() // 所有人可访问
				.anyRequest().authenticated() // 其他url都需要登陆才能访问
			.and() // 前面antMatchers等相当于authorizeRequests的子标签，and将标签闭合
			.formLogin()
				.loginPage("/login.html") // 指定登陆页面url
				.loginProcessingUrl("/perform_login") // 处理登陆的url
				.defaultSuccessUrl("/homepage.html", true) // 登陆成功重定向到该页面
				.failureHandler(authenticationFailureHandler())
			.and()
			.logout()
				.logoutUrl("/perform_logout") //指定登出请求的url
				.deleteCookies("JSESSIONID")
				.logoutSuccessHandler(logoutSuccessHandler())
			.and()
			.exceptionHandling()
				.accessDeniedHandler(accessDeniedHandler());
	}

	/**
	 * 密码hash算法
	 * 
	 * @return
	 */
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	/**
	 * 认证失败后的处理器
	 * 
	 * @return
	 */
	@Bean
	public AuthenticationFailureHandler authenticationFailureHandler() {
		return new CustomAuthenticationFailHandler();
	}

	/**
	 * 退出登陆处理器
	 * @return
	 */
	@Bean
	public LogoutSuccessHandler logoutSuccessHandler() {
		return new CustomLogoutHandler();
	}

	/**
	 * 权限验证失败处理器
	 * @return
	 */
	@Bean
	public AccessDeniedHandler accessDeniedHandler() {
		return new CustomAccessDeniedHandler();
	}

}
