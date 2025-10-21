package org.example.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

import java.util.Map;

@Slf4j
@Component
public class UserHeadersGatewayFilterFactory extends AbstractGatewayFilterFactory<UserHeadersGatewayFilterFactory.Config> {

    public UserHeadersGatewayFilterFactory() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> ReactiveSecurityContextHolder.getContext()
                .map(securityContext -> securityContext.getAuthentication())
                .filter(authentication -> authentication instanceof JwtAuthenticationToken)
                .map(authentication -> (JwtAuthenticationToken) authentication)
                .map(jwtAuth -> {
                    Jwt jwt = jwtAuth.getToken();

                    log.info("Extracting user info from JWT");

                    // Extract user info from JWT
                    String userId = jwt.getSubject();
                    String email = jwt.getClaim("email");
                    String firstName = jwt.getClaim("given_name");
                    String lastName = jwt.getClaim("family_name");
                    String preferredUsername = jwt.getClaim("preferred_username");

                    // Extract roles
                    String roles = extractRoles(jwt);

                    log.info("User ID: {}, Email: {}, Roles: {}", userId, email, roles);

                    // Add headers to downstream request
                    return exchange.mutate()
                            .request(request -> request
                                    .header("X-User-Id", userId != null ? userId : "")
                                    .header("X-User-Email", email != null ? email : "")
                                    .header("X-User-FirstName", firstName != null ? firstName : "")
                                    .header("X-User-LastName", lastName != null ? lastName : "")
                                    .header("X-User-Username", preferredUsername != null ? preferredUsername : "")
                                    .header("X-User-Roles", roles)
                            )
                            .build();
                })
                .defaultIfEmpty(exchange)
                .flatMap(chain::filter);
    }

    private String extractRoles(Jwt jwt) {
        try {
            Map<String, Object> resourceAccess = jwt.getClaim("resource_access");
            if (resourceAccess != null && resourceAccess.containsKey("autoally-rest-api")) {
                Map<String, Object> resource = (Map<String, Object>) resourceAccess.get("autoally-rest-api");
                if (resource != null && resource.containsKey("roles")) {
                    return String.join(",", (Iterable<String>) resource.get("roles"));
                }
            }
        } catch (Exception e) {
            log.error("Error extracting roles from JWT", e);
        }
        return "";
    }

    public static class Config {
        // Configuration properties if needed
    }
}