package com.xareen.polls.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController

public class TestController {

    @GetMapping("/test")
    private ResponseEntity<String> responseEntity(){
        return new ResponseEntity<>("dziaua", HttpStatus.OK);
    }
}
