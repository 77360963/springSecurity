package haha.otaku.springSecurity.config;

import java.util.Locale;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.i18n.CookieLocaleResolver;
import org.springframework.web.servlet.i18n.LocaleChangeInterceptor;
import org.thymeleaf.extras.springsecurity5.dialect.SpringSecurityDialect;

/**
 * 开启SpringSecurity特性
 *SpringSecurity默认保护所有的url，并自动生成登陆url和页面
 *
 */
@EnableWebMvc
@Configuration
public class WebMvcConfig implements WebMvcConfigurer {
	
	/**
	 * 配置一些导航到模板的url
	 */
	@Override
	public void addViewControllers(ViewControllerRegistry registry) {
		registry.addViewController("/login.html");
		registry.addViewController("/anonymous.html");
		registry.addViewController("/homepage.html");
		registry.addViewController("/accessDenied");
		registry.addViewController("/admin/adminpage.html");
	}
	
	/**
	 * 配置thymeleaf spring security
	 * @return
	 */
	@Bean
	public SpringSecurityDialect templateDialect() {
		return new SpringSecurityDialect();
	}
	
	//-------------------------------国际化配置
	
	/**
	 * 用于改变Local的拦截器，如页面带上lang参数，若lang=zh_CN，则Local变为Chinese
	 */
	@Override
	public void addInterceptors(InterceptorRegistry registry) {
		LocaleChangeInterceptor localeChangeInterceptor = new LocaleChangeInterceptor();
		localeChangeInterceptor.setParamName("lang");
		registry.addInterceptor(localeChangeInterceptor);
	}
	
	/**
	 * 国际化策略，使用cookie保存用户的国际化信息
	 * @return
	 */
	@Bean
	public LocaleResolver localeResolver() {
		CookieLocaleResolver localeResolver = new CookieLocaleResolver();
		localeResolver.setDefaultLocale(Locale.US);
		return localeResolver;
	}
	
}
