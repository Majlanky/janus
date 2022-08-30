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

import org.springframework.lang.NonNull;

import java.util.Base64;

/**
 * Helper class which provides method to get PEMs formatted key content.
 *
 * @author Majlanky
 */
public class KeySpec {

    private KeySpec() {}

    /**
     * @param keyValue PEM formatted key. Must not be {@literal null}
     * @return Base64 containing key stripped from PEM header and footer
     */
    public static byte[] getDecoded(@NonNull String keyValue) {
        keyValue = keyValue.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "");
        return Base64.getMimeDecoder().decode(keyValue);
    }

}
