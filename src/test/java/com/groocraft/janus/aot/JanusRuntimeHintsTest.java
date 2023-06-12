/*
 * Copyright 2023 the original author or authors.
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

package com.groocraft.janus.aot;

import com.groocraft.janus.security.IdentityProviders;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.aot.hint.RuntimeHints;

import java.util.function.Consumer;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class JanusRuntimeHintsTest {

    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    RuntimeHints runtimeHints;

    @Test
    void test() {
        JanusRuntimeHints hints = new JanusRuntimeHints();
        hints.registerHints(runtimeHints, this.getClass().getClassLoader());

        verify(runtimeHints.reflection()).registerType(eq(IdentityProviders.class), any(Consumer.class));
    }

}