package testCSRF;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class LoginServlet extends HttpServlet {

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		Object usernameObj =  request.getAttribute("username");
		Object passwordObj =  request.getAttribute("password");
		
		usernameObj = "admin";
		passwordObj = "admin";
		
		String referer =  request.getHeader("Referer");
		System.out.println("referer:"+referer);
		
		if("http://localhost:8080/Distributed3/".equals(referer)) {
			if(usernameObj != null && passwordObj != null) {
				String username = usernameObj.toString().trim();
				String password = passwordObj.toString();
				
				if("admin".equals(username) && "admin".equals(password)) {
					Cookie loginCookie = new Cookie("username",username);
					loginCookie.setMaxAge(30*60);//30min过期
					response.addCookie(loginCookie);
					
					response.setHeader("Set-Cookie", "cookiename=loginCookie;HttpOnly");//设置cookie为HttpOnly
					response.setContentType("text/html;charset=utf-8");
					PrintWriter out = response.getWriter();
					out.println("login success!");
					out.close();
					
				}else {
					response.setContentType("text/html;charset=utf-8");
					PrintWriter out = response.getWriter();
					out.println("login fail!");
					out.close();
				}
				
			}else {
				response.setContentType("text/html;charset=utf-8");
				PrintWriter out = response.getWriter();
				out.println("login fail!");
				out.close();
			}
		}else {
			response.setContentType("text/html;charset=utf-8");
			PrintWriter out = response.getWriter();
			out.println("login fail!");
			out.close();
		}
	}
}
