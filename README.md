# Overview of Spring Boot JWT Authentication 
We will build a Spring Boot application in that:

- User can signup new account, or login with username & password.
- By User’s role (admin, moderator, user), we authorize the User to access resources

This is our Spring Boot application demo running with MySQL database and test Rest Apis with Postman.

Tutorial link : [Spring Security & JWT](https://bezkoder.com/spring-boot-jwt-authentication/)

![Capture](https://user-images.githubusercontent.com/49534121/112665208-b8927300-8e52-11eb-9460-a4a51d3f13e6.PNG)

create role = http://localhost:8080/api/v1/roles
{
	"name" : "ROLE_ADMIN",
	"permissions" : [
		{
			"action" : "READ"
		},
		{
			"action" : "DELETE"
		},
		{
			"action" : "UPDATE"
		}
	]
}

create admin = http://localhost:8080/api/v1/auth/signup
{
	"username" : "booba",
	"password" : "password",
	"email" : "booba@gmail.com",
	"roles" : [
		{
			"name" : "admin"
		},
		{
			"name" : "mod"
		}
	]
}

connect = http://localhost:8080/api/v1/auth/signin
with
 {
	"username" : "booba",
	"password" : "password"
}

