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
