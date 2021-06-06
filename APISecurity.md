API Styles
- RPC 
- RMI
- REST
- GraphQL
##### API Security in Context
- API security lies at the intersection of several security disciplines
1. InfoSec
2. Network Security
3. Application Security

From Information Security you will learn how to 
- Define your security goals and identify threats
- Protect your APIs using access control techniques
- Secure information using applied cryptography

From Network security
- The basic infrastructure used to protect an API on the internet, including firewalls, load-balances, and reverse proxies, and roles they play in protecting your API
- Use of secure communication protocols such as HTTPS to protect data transmitted to or from your API

From Application Security
- Secure Coding Techniques
- Common Software Security vulnerabilites
- How to store and manage system and user credentials used to access your APIs

Specialist Services
- API gateway is a specialized reverse proxy that can make different APIs appear as if they are single API. They are often used within a microservice architecture to simplify the API presented to clients. API gateways can often also take care of some of the aspects of API security discussed in this book, such as authentication or rate-limiting.
- A web application firewall (WAF) inspects traffic at a higher level than a traditional firewall and can detect and block many common attacks against HTTP web services.
- An intrusion detection system (IDS) or intrusion prevention system (IPS) monitors traffic within your internal netork. When it detects suspicious patterns of activity it can either raise an alert or actively attempt to block the suspicious traffic.

##### Elements of API Security
- Same API may be accessible to users with distinct levels of authority
- While each individual operation in an API may be secure on its own, combinations of operations might not be.
- There maybe security vulnerabilites due to the implementation of the API.

###### Assets
- If anybody would suffer real or perceived harm if some part of the system were compromised, that part should be considered an `asset to be protected.`

###### Security Goals
- Confidentiality
- Integrity
- Availability

Defining security for your API consists of a four-step iterative process of identifying assets, defining the security goals that you need to preserve for those assets, and then breaking those down into testable implementation constraints. 
- Implementation may then identify new assets or goals and so the process continues.

###### Environments and Threat Models
- A good definition of API security must also consider the `environment` in which your API is to operate and the potential threats that will exist in that environment.
- A `threat` is simply any way that a security goal might be violated with respect to one or more of your assets.
- The set of threats that you consider relavent to your API is known as your `threat model` and the process of identifying is known as `threat modeling`.

###### Identifying Threats

- Many attacks fall into a few known categories. Several methodologies have been developed to try to systematically identify threats to software systems, and we can use these to identify the kinds of threats that might befall your API.
- One very popular methodology is known by the acronym STRIDE, which stands for
1. Spoofing -> pretending to be someone else.
2. Tampering -> altering data, messages, or settings you're not supposed to alter
3. Repudiation -> Denying that you did something that you really did do.
4. Information discolosure -> Revealing information that should be kept private
5. Denial of service -> preventing others from accessing information and services
6. Elevation of privilege -> Gaining access to functionality you're not supposed to have access to.

###### Security Mechanisms
- Encryption
- Authentication
- Access Control
- Audit logging
- Rate limiting

Access Control and Authorizations
- Identity based access control first identifies the user and then determines what they can do based on who they are. A user can try to access any resource but they may be denied access based on access control rules.
- Capability-based access control uses special tokens or keys known as `capabilities` to access an API.
- The capability itself says what operations the `bearer` can perform rather than who the user is.
- A capability both names a resource and describes the permissions on it, so a user is not able to access any resource that they do not have a capability for.

 #### Case Study - Natter API
 - Natter API is split into two REST endpoints, one for normal users and one for moderators who have special privileges to tackle abusive behavior.
 - POST /spaces -> returns `space id`
 - POST /spaces/<spaceid>/messages 
 - GET /spaces/<spaceid>/messages. -> to return messages in a space. A `since=<timestamp>` query parameter can be used to limit the messges returned to a recent period.
 - Moderator API contains a single operation to delete a message by sending a `DELETE` request to the message URI.
 - An injection attack can occur anywhere that you execute dynamic code in response to user input, such as SQL and LDAP queries, and when running operating system commands.
 - An Injection Attack occurs when unvalidated user input is included directly in a dynamic command or query that is executed by the application, allowing an attacker to control the code that is executed.
 - Best approach to prevent injection atacks is to ensure that user input is always clearly separated from dynamic code by using APIs that support `prepared statements`.
 - A prepared statement allows you to write the command or query that you want to execute with placeholders in it for user input. You then separately pass the user input values and the database API ensures they are never treated as statements to be executed.
 - Database user didn't need to have permissions to delete tables in the first place.
 - Buffer Overflow attack.
 - Remote code execution occurs when an attacker can inject code into a remotely running API and cause it to execute. This can allow the attacker to perform actions that would not normally be allowed.
 - Insecure Deserialization
 - ReDos Attacks
 - Cross Site Scripting
 - Single Origin Policy -> Scripts executing within the same origin (or same site) as a web page are, by default, able to read cookies set by that website, examine HTML elements created by that site, make network requests to that site, and so on, although scripts from other origins are blocked from doing those things.
 - A successful XSS allows an attacker to execute their script as if it came from the target origin, so the malicious script gets to do all the same things that the genuine scripts from that origin can do. 
 - If I can successfully exploit an XSS vulnerability on facebook.com, for example, my script could potentially read and alter your Facebook posts or steal your private messages.
 - Although XSS is primarily a vulnerability in web applications, in the age of single page apps, it's a common for web browser clients to talk directly to an API. 
 - For this reason it's essential that an API take basic precautions to avoid producing output that might be interpreted as a script when processed by a web browser.
 - `X-XSS-Protection` header is usually used to ensure browser protections are turned on.
 - How to prevent XSS?
 1. Be string in what you accept.
 2. Ensure all outputs are well-formed using a proper json library rather than by concatenating strings.
 3. Produce correct Content_type headers on all your API's reponses, and never assume the defualts are sensible.
 4. If you parse the Accept header to decide wht kind of output to produce, never simply copy the value of that header into the response. Always explicitly specify the `Content-Type` that your API has produced.
 - `X-Content-Type-Options` -> `Set to nosniff to prevent the browser guessing the correct Content-Type.`
 - `X-Frame-Options` -> `Set to DENY to prevent your API responses being loaded in a frame or iframe.`
 - `Cache-Control` and `Expires`
 
 #### Applying Security Controls
 - Encryption prevents information disclosure.
 - Rate Limiting protects availability.
 - Authentication is used to ensure that users are who they say they are.
 - Audit logging records who did what, to support accountability.
 - Access Control is then applied to enforce integrity and confidentiality.
- An important detail, is that `only rate-limiting and access control directly reject requests`. A failure in authentication does not immediately cause a request to fail, but a later access control decision may reject a request if it is not authenticated. This is important because we want to ensure that even failed requests are logged, which they would not be if the authentication process immediately rejected unauthenticated requests.
##### Rate-limiting for availability
- In a DNS amplification attack, the attacker sends the same DNS query to many DNS servers, spoofing their IP address to look like the request came from the victim. By carefully choosing the DNS query, the server can be tricked into replying with much more data than was in the original query, flooding the victim with traffic.
- Amplification attacks usually exploit weaknesses in protocols based on UDP (User Datagram Protocol), which are popular in the Internet of Things. 
- Rate-limiting should be the very first security decision made when a request reaches your API. Because the goal of rate-limiting is ensuring that your API has enough resources to be able to process accepted requests, you need to ensure that requests that exceed your API's capacities are rejected quickly and very early in processing. Other security controls such as authentication, can use significant resources, so rate-limiting must be applied before those processes.
- Often rate-limiting is applied at a reverse proxy, API gateway, or load balancer before the request reaches the API, so that it can be applied to app requests arriving at a cluster of servers.
- Even if you enforce rate-limiting at a proxy server, it is a good security practice to also enforce rate limits in each server so that if the proxy server misbehaves or is misconfigured, it is still difficult to bring down the individual servers. This is an instance of the general security principle known as `defence in depth`, which aims to ensure that no failure of a single mechanism is enough to compromise your API.
- The rate limit for individual servers should be a fraction of the overall rate limit you want your service to handle. If your service needs to handle a thousand requests per second, and you have 10 servers, then the per-server rate limit should be around 100 requests per second. You should verify that each server is able to handle this maximum rate.

#### Authentication To prevent Spoofing
- Apart from rate-limiting, authentication is the first process we perform. 
- Downstream security controls, such as audit logging and access control, will almost always need to know who the user is. It is important to realize that the authentication phase itself shouldn't reject a request even if authentication fails. 
- Deciding whether any particular request requires the user to be authenticated is the job of `access control`, and your API may allow some requests to be carried out anonymously.
- Instead, the authentication process will populate the request with attributes indicating whether the user was correctly authenticated that can be used by these downstream processes.

##### HTTP Basic Authentication
- There are many ways of authenticating a user, but one of the most widespread is simple username and password authentication.
- In a web application with a user interface, we might implement this by presenting the user with a form to enter their username and password.
- An API is not responsible for rendering a UI, so you can instead use the standard HTTP Basic Authentication mechanism to prompt for a password in a way that doesn't depend on any UI.
- This is a simple standard scheme, specified in RFC 7617 in which the username and password are encoded and sent in a header.
- An example of a Basic authentication header for the username demo and password changeit is as follows:
```
Authorization: Basic ZGVtbzpjaGFuZ2VpdA==
```
- The Authorization header is a standard HTTP header for sending credentials to the server.
- It's extensible, allowing different authentication schemes.
- HTTP Basic credentials are easy to decode for anybody able to read network messages between the client and the server. You should only ever send passwords over an encrypted connection. 

##### Secure Password Storage with SCRYPT
- A password hashing algorithm converts passwords into random-looking fixed-size values known as `hash`. A secure password hash uses a lot of time and memory to slow down brute-force attacks such as `dictionary attacks`, in which an attacker tries a list of common passwords to see if any match the hash.
- When the user tries to login, the password they present is hashed using the same algorithm and compared to the hash stored in the database. This allows the password to be checked without storing it directly.
- Modern password hashing algorithms, such as Argon2, Scrypt, Bcrypt, or PBKD-F2 are designed to resist a variety of attacks in case the hashed passwords are ever stolen. In particular, they are designed to take a lot of time or memory to process to prevent brute-force attacks to recover passwords. 
```
Establish secure defaults for all security-sensitive algorithms and parameters used in your API. Only relax the values if there is no other way to achieve your non-security requirements.
```
- Scrypt library generates a unique random salt value for each password hash. The hash string that gets stored in the database includes the `parameters that were used when the hash was generated, as well as the random salt value`. This ensures that you can always recreate the same hash in the future, even if you change the parameter. 
- The Scrypt library will be able to read this value and decode the parameters when it verifies the hash.
```
A salt is a random value that is mixed into the password when it is hashed. Salts ensure that the hash is always different even if two users have the same password. Without salts, an attacker can build a compressed database of common password hashes, known as a rainbow table, which allows passwords to be recovered very quickly.
```
##### Authenticating Users
- To authenticate a user, you'll extract the username and password from the HTTP Basic authentication header, look up the corresponding user in the database, and finally verify the password matches the hash stored for that user.
- Behind the scenes, the Scrypt library will extract the salt from the stored password hash, then hash the supplied password with the same salt and parameters, and then finally compare the hashed password with the stored hash. if they match, then the user much have presented the same passord and so authentication succeeds, otherwise it fails.

#### Using Encryption to keep data private

- Introducing authentication into you API protects against spoofing threats. However, requests to API and responses from it, are not protected in any way, leading to tampering and information disclosure threats.
- If often the case that threats are linked together in this way.
- An attacker can take advantage of one threat, in this case information disclosure from unencrypted communications, and exploit that to pretend to be somebody else, undermining your API's authentication.
- Many successful real-world attacks result from chaining together multiple vulnerabilities rather than exploiting just one mistake.
- To enable HTTPS support, you need to `generate a certificate that the API will use to authenticate itself to its clients.`
- When a client connects to your API it will use a URI that includes the hostname of the server the API is running on, for example `api.example.com`
- The server must present a certificate, signed by a trusted certificate authority (CA), that says that it really is the server for `api.example.com`
- If an invalid certificate is presented, or it doesn't match the host that the client wanted to connect to, then the client will abort the connection. 
- Without this step, the client might be tricked into connecting to the wrong server and then send its password or other confidential data to the imposter.
- Enabling HTTPS for development purposes, you could use a self-signed certificate.
- A self-signed certificate is a certificate that has been `signed using the private key associated with that same certificate`, rather than by a trusted certificate authority. Self-signed certificates should be used only when you have a direct trust relationship with the certificate owner, such as when you generated the certificate yourself.

#### Audit logging for accountability
- Accountability relies on being able to determine who did what and when. The simplest way to do this is to keep a log of actions that people perform using your API, known as an `audit log`.
- Audit logging should occur after authentication, so that you know who is performing an action, but before you make authorization decisions that may deny access.
- The reason for this is that you want to record all attempted operations, not just the successful ones.
- Unsuccessful attempts to perform actions may be indications of an attempted attack.
- It's difficult to overstate the importance of good audit logging to the security of an API.
- Audit logs should be written to durable storage such as file system or a database, so that the audit logs will survive if the process crashes for any reason.
- If implementing audit table in database, it should not have any reference constraints to any other tables. Audit logs should be recorded based on the request, even if the details are inconsistent with other data.
- Logging can be split into two filters, one that occurs before the request is processed (after authentication) and one that occurs after the response has been produced. 
- Another way to create an audit log is to capture events in the business logic layer of you application, such as User Created or Messaged Posted events.
- These events describe the essential details of what happened without reference to the specific protocol used to access the API.
- Yet another approach is to capture audit events directly in the database using triggeres to detect when data is changed.
- The advantage of these alternative approaches is that they ensure that events are logged no matter how the API is accessed, for example, if the same API is available over HTTP or using a binary RPC protocol.
- The disadvantage is that some details are lost, and some potential attacks maybe missed due to this missing detail.

#### Access Control
- Access control should happen after authentication, so that you know who is trying to perform the action.
- If the request is granted, then it can proceed through to the application logic. However, if it is denied by the access control rules, then it should be failed immediately, and an error response returned to the user.
- The two main HTTP status codes for indicating that access has been denied are `401 Unauthorized` and `403 Forbidden`.

##### Enforcing Authentication
- The most basic access control check is simply to require that all users are authenticated.
- This ensures that only genuine users of the API can gain access, while not enforcing any further requirements.
- You can enforce this with a simple filter that runs after authentication and verifies that a genuine subject has been recorded in the request attributes.
- If no subject attribute is found, then it rejects the request with a 401 status code and adds a standard `WWW-Authenticate` header to inform the client that the user should authenticate with Basic authentication.
##### Access Control Lists
- Beyond simply requiring that users are authenticated, you may also want to impose additional restrictions on who can perform certain operations.
- An access control list is a list of users that can access a given object, together with a set of permissions that define what each user can do.
- Access contro lchecks are often included directly in business logic, because who has access to what is ultimately a business decision. This also ensures that access control rules are consistently applied no matter how the functionality is accessed. 
- On the other hand, separating out the access control checks makes it easier to centralize policy management.
##### Avoiding Privilege Escalation Attacks
- A privilege escalation occurs when a user with limited permissions can exploit a bug in the system to grant themselves or somebody else more permissions than they have been granted.
- This can be fixed in two ways:
1. You can require that the permissions granted to the new user are no more than the permissions that are granted to the existing user.
2. You can require that only users with all permissions can add other users.