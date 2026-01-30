<h1>Secure Auth Backend</h1>

<p>
  Simple Spring Boot backend that demonstrates 
  <strong>JWT authentication</strong>, 
  <strong>Google OAuth2 login</strong> 
  and <strong>role-based access control</strong>.
</p>

<p>The project is used as a demo API for a future frontend client.</p>

<hr />

<h2>Tech stack</h2>
<ul>
  <li>Java 17+</li>
  <li>Spring Boot 3</li>
  <li>Spring Security 6</li>
  <li>Spring Data JPA</li>
  <li>JWT (io.jsonwebtoken)</li>
  <li>OAuth2 Login (Google)</li>
  <li>JUnit + Spring Test (MockMvc)</li>
</ul>

<hr />

<h2>Features</h2>
<ul>
  <li>Register new user with email &amp; password</li>
  <li>Login with email &amp; password and get JWT access token</li>
  <li>Login with <strong>Google Account</strong> (OAuth2)</li>
  <li>Store users &amp; roles in the database</li>
  <li>Protected endpoints for <code>ROLE_USER</code> and <code>ROLE_ADMIN</code></li>
  <li>Integration tests for main scenarios (login / register / current user)</li>
</ul>

<hr />

<h2>Local setup</h2>

<h3>1. Prerequisites</h3>
<ul>
  <li>JDK 17+</li>
  <li>Maven 3.9+</li>
  <li>Any SQL database supported by Spring Data JPA (e.g. PostgreSQL)</li>
</ul>

<h3>2. Configuration</h3>

<p>Create a local config file, for example:</p>
<p><code>src/main/resources/application-local.properties</code>:</p>

<pre><code># Database
spring.datasource.url=jdbc:postgresql://localhost:5432/secure_auth
spring.datasource.username=your_db_user
spring.datasource.password=your_db_password

spring.jpa.hibernate.ddl-auto=update

# JWT
jwt.secret=change_me_super_secret_key
jwt.expiration-seconds=3600

# Google OAuth2
spring.security.oauth2.client.registration.google.client-id=YOUR_GOOGLE_CLIENT_ID
spring.security.oauth2.client.registration.google.client-secret=YOUR_GOOGLE_CLIENT_SECRET
spring.security.oauth2.client.registration.google.scope=openid,profile,email

spring.security.oauth2.client.provider.google.issuer-uri=https://accounts.google.com
</code></pre>
