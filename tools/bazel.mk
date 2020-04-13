#!/usr/bin/make -f

# Copyright 2018 The gVisor Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

include tools/images.mk

NAME ?= gvisor-bazel
USER ?= gvisor
UID := $(shell id -u ${USER})
GID := $(shell id -g ${USER})
BAZEL := bazel
BAZEL_CACHE := $(shell readlink -f ~/.cache/bazel/)

# The  --privileged is required to run tests.
DOCKER_RUN_OPTIONS ?= --privileged

bazel-shutdown:
	docker exec -i $(NAME) bazel shutdown && docker kill $(NAME)
.PHONY: bazel-shutdown

bazel-alias:
	@echo "alias bazel='docker exec -u $(UID):$(GID) -i $(call local_image,default) bazel'"
.PHONY: bazel-alias

bazel-server-start: load-default register-cross
	mkdir -p "$(BAZEL_CACHE)" && \
	docker run -d --rm \
	        --name $(NAME) \
		--user 0:0 \
		-v "$(HOME)/.cache/bazel:$(BAZEL_CACHE)" \
		-v "$(CURDIR):/workspace" \
		-v /var/run.docker.sock:/var/run/docker.sock \
		--tmpfs /tmp:rw,exec \
		--entrypoint "" \
		$(DOCKER_RUN_OPTIONS) \
		$(call local_image,default) \
		sh -c "while :; do sleep 100; done" && \
	docker exec --user 0:0 -i $(NAME) \
		sh -c "groupadd --gid $(GID) --non-unique $(USER) && useradd --uid $(UID) --non-unique --gid $(GID) -d $(HOME) $(USER)"
.PHONY: bazel-server-start

# bazel-server ensures that the container exists, otherwise starts a server.
# This is the requisite command for bazel below.
bazel-server:
	docker exec $(NAME) true || $(MAKE) bazel-server-start
.PHONY: bazel-server

# do executes a command in the context of the bazel server. This is the command
# that is called recursively by all other metarules defined in the top-level of
# the Makefile. We define as a function here to avoid recursive calls.
do: bazel-server
	docker exec --user $(UID):$(GID) -i $(NAME) bazel $(OPTIONS)
.PHONY: do
