# GovTechTakeHomeAssignment
1. [POST] `/user/register`
  - User register his account with `username`, `full_name`, `password`.

2. [POST] `/user/login`
  - User login his acccount using his `username` and `password`.
  - Upon successful login, the web service will return a JWT token, which user can use it for other API request.  

3. [GET] `/user/profile`
  - User can get his own profile (username and full_name).
  - User needs to send in JWT token for authentication.
