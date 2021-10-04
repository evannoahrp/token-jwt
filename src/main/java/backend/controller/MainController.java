package backend.controller;

import backend.config.responseException.Forbidden;
import backend.repository.UserRepository;
import backend.service.oauth.Oauth2UserDetailsService;
import backend.service.oauth.RolePathChecker;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

@RestController
public class MainController {

    private final Oauth2UserDetailsService oauth2UserDetailsService;

    private final RolePathChecker rolePathChecker;

    @Autowired
    public MainController(Oauth2UserDetailsService oauth2UserDetailsService,
                          RolePathChecker rolePathChecker) {
        this.oauth2UserDetailsService = oauth2UserDetailsService;
        this.rolePathChecker = rolePathChecker;
    }

    @RequestMapping("/")
    public Map<String, Boolean> indexAction() {
        Map<String, Boolean> response = new HashMap<>();
        response.put("success", true);
        return response;
    }

    @RequestMapping("/oauth/authenticate")
    public Map<String, String> authenticateAction(
            @RequestParam Map<String, String> query,
            HttpServletResponse response,
            HttpServletRequest request,
            Principal principal) throws RuntimeException {
        String username = principal.getName();
        UserDetails user = null;

        String xUri = request.getHeader("X-Uri");
        if (StringUtils.isEmpty(xUri) && query.containsKey("uri")) {
            xUri = query.get("uri");
        }
        if (!StringUtils.isEmpty(username)) {
            user = oauth2UserDetailsService.loadUserByUsername(username);
        }
        if (null == user) {
            throw new UsernameNotFoundException("User not found");
        }
        if (!rolePathChecker.isAllow(user, xUri, request.getMethod())) {
            throw new Forbidden("Not enough access to this endpoint");
        }
        response.addHeader("X-User", user.getUsername());
        Map<String, String> userFound = new HashMap<>();
        userFound.put("username", user.getUsername());
        return userFound;
    }

}

