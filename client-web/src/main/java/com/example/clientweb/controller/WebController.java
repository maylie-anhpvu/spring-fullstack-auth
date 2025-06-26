package com.example.clientweb.controller;

import org.springframework.http.*;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.HttpSession;
import java.util.Map;

@Controller
public class WebController {

    private final RestTemplate restTemplate = new RestTemplate();

    @GetMapping("/login")
    public String loginForm() {
        return "login";
    }

    @PostMapping("/login")
    public String loginSubmit(@RequestParam String username, @RequestParam String password, HttpSession session, Model model) {
        ResponseEntity<Map> response = restTemplate.postForEntity("http://localhost:8081/auth/login",
                Map.of("username", username, "password", password), Map.class);

        if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
            session.setAttribute("token", response.getBody().get("token"));
            session.setAttribute("username", username);
            return "redirect:/dashboard";
        }
        model.addAttribute("error", "Login failed");
        return "login";
    }

    @GetMapping("/dashboard")
    public String dashboard(Model model, HttpSession session) {
        String token = (String) session.getAttribute("token");
        String username = (String) session.getAttribute("username");
        if (token == null) return "redirect:/login";

        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + token);
        HttpEntity<String> entity = new HttpEntity<>(headers);
        ResponseEntity<String> apiResponse = restTemplate.exchange("http://localhost:8082/api/user", HttpMethod.GET, entity, String.class);

        model.addAttribute("username", username);
        model.addAttribute("apiData", apiResponse.getBody());
        return "dashboard";
    }
}