package com.hackerrank.springsecurity.controller;

import com.hackerrank.springsecurity.dto.ApiResponse;
import com.hackerrank.springsecurity.dto.Course;
import com.hackerrank.springsecurity.dto.Student;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CourseController {

    @RequestMapping(value = "/course", method = RequestMethod.POST, produces = MediaType.APPLICATION_JSON_VALUE)
    @Secured("ROLE_OFFICE_ADMIN")
    public ResponseEntity<ApiResponse> addCourse(@RequestBody Course course, Authentication auth) {
      if (!authentication.getAuthorities()
      .stream()
      .anyMatch(auth -> auth.getAuthority().equals("ROLE_OFFICE_ADMIN"))) {
        ApiResponse response = new ApiResponse(403, "Authorization Failure - This user does not have the sufficient level of access");
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
      }else  return new ResponseEntity(new ApiResponse(200, "Added"), HttpStatus.OK);
    }

    @RequestMapping(value = "/student", method = RequestMethod.POST, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ApiResponse> registerStudent(@RequestBody Student student) {
        return new ResponseEntity(new ApiResponse(200, "Added"), HttpStatus.OK);
    }

    @RequestMapping(value = "/course", method = RequestMethod.GET, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ApiResponse> getCourses() {
        return new ResponseEntity(new ApiResponse(200, "Courses"), HttpStatus.OK); 
    }
}