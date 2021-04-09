package springsecurity.JwtAuthentication.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import springsecurity.JwtAuthentication.models.Permission;
import springsecurity.JwtAuthentication.models.Role;
import springsecurity.JwtAuthentication.models.User;
import springsecurity.JwtAuthentication.repositories.PermissionRepository;
import springsecurity.JwtAuthentication.security.jwt.JwtResponse;
import springsecurity.JwtAuthentication.repositories.RoleRepository;
import springsecurity.JwtAuthentication.repositories.UserRepository;
import springsecurity.JwtAuthentication.security.jwt.JwtUtils;
import springsecurity.JwtAuthentication.security.services.UserDetailsImpl;

import javax.validation.Valid;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/v1")
public class AuthController {
    @Autowired
    AuthenticationManager authenticationManager;
    @Autowired
    UserRepository userRepository;
    @Autowired
    RoleRepository roleRepository;
    @Autowired
    PermissionRepository permissionRepository;
    @Autowired
    PasswordEncoder encoder;
    @Autowired
    JwtUtils jwtUtils;

    // ## This controller provides APIs for register and login actions.
    // – /api/auth/signin
    //      - authenticate { username, pasword }
    //      - update SecurityContext using Authentication object
    //      - generate JWT
    //      - get UserDetails from Authentication object
    //      - response contains JWT and UserDetails data
    @PostMapping("/auth/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody User user) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        return ResponseEntity.ok(new JwtResponse(jwt,
                userDetails.getId(),
                userDetails.getUsername(),
                userDetails.getEmail(),
                roles));
    }

    // – /api/auth/signup
    //      - check existing username/email
    //      - create new User (with ROLE_USER if not specifying role)
    //      - save User to database using UserRepository
    @PostMapping("/auth/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody User user) {

        if (userRepository.existsByUsername(user.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body("Error: Username is already taken!");
        }

        if (userRepository.existsByEmail(user.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body("Error: Email is already in use!");
        }

        // Create new user's account
        Set<Role> listRoles = user.getRoles();
        Set<Role> roles = new HashSet<>();

        if (listRoles == null) {
            Role userRole = roleRepository.findByName("ROLE_USER")
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        } else {
            listRoles.forEach(role -> {
                switch (role.getName()) {
                    case "admin":
                        Role adminRole = roleRepository.findByName("ROLE_ADMIN")
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(adminRole);

                        break;
                    case "mod":
                        Role modRole = roleRepository.findByName("ROLE_MODERATOR")
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(modRole);

                        break;
                    default:
                        Role userRole = roleRepository.findByName("ROLE_USER")
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(userRole);
                }
            });
        }

        User userTmp = new User(user.getUsername(), user.getEmail(), encoder.encode(user.getPassword()));
        userTmp.setRoles(roles);
        userRepository.save(userTmp);

        return ResponseEntity.ok("User registered successfully!");
    }

    @PostMapping("/roles")
    public ResponseEntity<?> createRole(@Valid @RequestBody Role role) {
        Set<Permission> listPermissions = new HashSet<>();
        role.getPermissions().forEach(item -> {
            Optional<Permission> permission = permissionRepository.findByAction(item.getAction());
            if(permission.isPresent()){
                listPermissions.add(permission.get());
            } else {
                Permission permissionTmp = new Permission();
                permissionTmp.setAction(item.getAction());
                listPermissions.add(permissionRepository.save(permissionTmp));
            }
        });
        role.setPermissions(listPermissions);
        Role tmpRole = roleRepository.save(role);
        return ResponseEntity.ok(tmpRole);
    }
}
