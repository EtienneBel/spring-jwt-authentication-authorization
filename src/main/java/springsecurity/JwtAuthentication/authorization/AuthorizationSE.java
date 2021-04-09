package springsecurity.JwtAuthentication.authorization;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import springsecurity.JwtAuthentication.models.Permission;
import springsecurity.JwtAuthentication.repositories.PermissionRepository;
import springsecurity.JwtAuthentication.repositories.UserRepository;

import java.util.Optional;

@Component("authorizationSE")
public class AuthorizationSE {
    @Autowired
    PermissionRepository privilegeRepo;

    public boolean can(String action, String role) {
        UserDetails userDetails = (UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        for (GrantedAuthority auth : userDetails.getAuthorities()) {
            if (auth.getAuthority().equals(role)) {
                Optional<Permission> privilege = privilegeRepo.findByAction(action);
                if (privilege.isPresent()) {
                    return true;
                }
            }
        }
        return false;
    }
}
