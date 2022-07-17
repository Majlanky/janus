/*
 * Copyright 2022 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.groocraft.janus.security;

import org.springframework.boot.context.properties.source.InvalidConfigurationPropertyValueException;
import org.springframework.core.io.Resource;
import org.springframework.util.Assert;
import org.springframework.util.StreamUtils;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;

/**
 * Class for a configuration of on IdP.
 *
 * @author mbabicky-ext
 */
@Getter
@Setter
public class IdentityProvider {

    @Setter(value = AccessLevel.PACKAGE)
    private String id;

    private String issuerUri;
    private String jwkSetUri;
    private String rolesClaimName = "roles";
    private String rolesAuthorityPrefix = "ROLE_";
    private String jwsAlgorithm = "RS256";
    private Resource publicKeyLocation;

    /**
     * @return public signature key read from the configured resource
     * @throws IOException if the resource can not be read
     */
    public String readPublicKey() throws IOException {
        String key = IdentityProviders.PREFIX + "." + "resourceserver." + id + ".public-key-location";
        Assert.notNull(this.getPublicKeyLocation(), "PublicKeyLocation must not be null.");
        if (!this.getPublicKeyLocation().exists()) {
            throw new InvalidConfigurationPropertyValueException(key, this.getPublicKeyLocation(),
                "Public key location does not exist");
        }
        try (InputStream inputStream = this.getPublicKeyLocation().getInputStream()) {
            return StreamUtils.copyToString(inputStream, StandardCharsets.UTF_8);
        }
    }

}
