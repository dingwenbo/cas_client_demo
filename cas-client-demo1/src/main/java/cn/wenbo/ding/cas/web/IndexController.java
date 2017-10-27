package cn.wenbo.ding.cas.web;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class IndexController {

	@RequestMapping(value={"", "index"})
	public String list(HttpServletRequest request, HttpServletResponse response, Model model) {
		
		return "index";
	}
	
	@RequestMapping(value={"error"})
	public String error(HttpServletRequest request, HttpServletResponse response, Model model) {
		
		return "error";
	}
	
	@RequestMapping(value = "logout")
	public String logout(HttpServletRequest request, HttpServletResponse response, Model model) throws IOException {
		Subject subject = SecurityUtils.getSubject();
		
		// 如果已经登录，则跳转到管理首页
		if(subject != null){
			subject.logout();
		}
		 return "redirect:/index";
	}
}
