package com.xareen.polls.controller;

import com.xareen.polls.exception.AppException;
import com.xareen.polls.model.Role;
import com.xareen.polls.model.RoleName;
import com.xareen.polls.model.User;
import com.xareen.polls.payload.ApiResponse;
import com.xareen.polls.payload.JwtAuthenticationResponse;
import com.xareen.polls.payload.LoginRequest;
import com.xareen.polls.payload.SignUpRequest;
import com.xareen.polls.repository.RoleRepository;
import com.xareen.polls.repository.UserRepository;
import com.xareen.polls.security.CustomUserDetailsService;
import com.xareen.polls.security.JwtTokenProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.validation.Valid;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    JwtTokenProvider tokenProvider;

    @Autowired
    CustomUserDetailsService customUserDetailsService;

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsernameOrEmail(),
                        loginRequest.getPassword()
                )
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);

        ArrayList<String> tokenInfo = tokenProvider.generateToken(authentication);
        String jwt = tokenInfo.get(0);
        Integer expiresIn = Integer.valueOf(tokenInfo.get(1));

        return ResponseEntity.ok(new JwtAuthenticationResponse(jwt, expiresIn));
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignUpRequest signUpRequest) {
        if(userRepository.existsByUsername(signUpRequest.getUsername())) {
            return new ResponseEntity(new ApiResponse(false, "Username is already taken!"),
                    HttpStatus.BAD_REQUEST);
        }

        if(userRepository.existsByEmail(signUpRequest.getEmail())) {
            return new ResponseEntity(new ApiResponse(false, "Email Address already in use!"),
                    HttpStatus.BAD_REQUEST);
        }

        // Creating user's account
        User user = new User(signUpRequest.getUsername(),
                signUpRequest.getEmail(), signUpRequest.getPassword());

        user.setPassword(passwordEncoder.encode(user.getPassword()));

//        Role userRole = roleRepository.findByName(RoleName.ROLE_USER)
//                .orElseThrow(() -> new AppException("User Role not set."));

        Role role = new Role(RoleName.ROLE_USER);

        user.setRoles(Collections.singleton(role));
//        Collections.singleton(userRole)

        User result = userRepository.save(user);

        URI location = ServletUriComponentsBuilder
                .fromCurrentContextPath().path("/api/users/{username}")
                .buildAndExpand(result.getUsername()).toUri();

        //return ResponseEntity.created(location).body(new ApiResponse(true, "User registered successfully"));
        return ResponseEntity.ok(new ApiResponse(true, result.getUsername()));
    }

    @PostMapping("/valid")
    public ResponseEntity validToken(@RequestHeader("Authorization") String token){
        String jwt = tokenProvider.getJwtFromRequest(token);
        if(jwt != null){
            String userId = tokenProvider.getUserIdFromJWT(jwt);
            UserDetails userDetails = customUserDetailsService.loadUserById(userId);
            if(userDetails != null){
                return  ResponseEntity.ok().build();
            }else{
                return  ResponseEntity.status(401).build();
            }
//            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
//            authentication.setDetails();
        }else{
            return ResponseEntity.status(401).build();
        }

    }
}