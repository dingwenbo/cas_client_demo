package cn.wenbo.ding.cas.web;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("user")
public class UserController {

	@RequestMapping(value={"index"})
	public String list(HttpServletRequest request, HttpServletResponse response, Model model) {
		
		return "user/index";
	}
	
}
