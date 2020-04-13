#!/usr/bin/make -f

# Copyright 2019 The gVisor Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# OPTIONS are the command line options & arguments provided to bazel. Most
# commands will be execute via a variant of 'make do OPTIONS="build //foo"'.
OPTIONS :=

# ARCH is the architecture used for the build. This may be overriden at the
# command line in order to perform a cross-build (in a limited capacity).
ARCH := $(shell uname -m)

default: runsc
.PHONY: default

# Load all bazel wrappers.
ifeq (,$(wildcard tools/google.mk))
include tools/bazel.mk
else
include tools/google.mk
endif

# Define macros that will expand to an aggregated blaze command executed via
# the do call. This allows us to pass any number of targets, e.g. test-foo,
# test-bar, and aggregate them in the PHONY "test" target for execution
# together. All these targets are PHONY of course, so there's no real sense
# about which one failed and which one didn't.
define wrapper
$(1)@%: $(1)
	@true
$(1):
	@$(MAKE) do OPTIONS="$(1) $(OPTIONS) $$(subst @,/,$$(patsubst $(1)@%,%,$$(filter $(1)@%,$(MAKECMDGOALS))))"
.PHONY: $(1)
endef

$(eval $(call wrapper,build))
$(eval $(call wrapper,test))
$(eval $(call wrapper,run))

# Standard entrypoints.
runsc:
	$(MAKE) do OPTIONS="build runsc"
.PHONY: runsc

unit-tests:
	$(MAKE) do OPTIONS="test pkg/... runsc/... tools/..."
.PHONY: unit-tests

tests:
	$(MAKE) do OPTIONS="test --test_tag_filter runsc_ptrace test/syscalls/..."
.PHONY: tests
