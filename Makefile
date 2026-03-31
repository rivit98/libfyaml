
.PHONY: build build-clean fuzz clean coverage coverage-run coverage-build clean-fuzz clean-fuzz-logs clean-coverage fuzz-logs ensure-build-dirs ensure-fuzz-dirs ensure-cov-dirs

PROJECT_NAME=libfyaml
FUZZ_ARGS?=-fork=1
FUZZ_DIR=$(shell realpath ../fuzz/${PROJECT_NAME})
FUZZ_DICT=./src/fuzz/yaml.dict
BUILD_DIR=./build
FUZZ_BIN=$(BUILD_DIR)/fuzz
FUZZ_COV_BIN=$(BUILD_DIR)/fuzz_cov
COV_DIR=$(FUZZ_DIR)/cov
COV_PROFDATA=$(COV_DIR)/merged.profdata
LLVM_PROFDATA?=llvm-profdata
LLVM_COV?=llvm-cov

# make build CC=afl-clang-fast CMAKE_ARGS=-DFUZZ_AFL_SANITIZER=msan
ifeq ($(origin CC),default)
CC := clang
endif
ifeq ($(origin CXX),default)
CXX := clang++
endif

CMAKE_ARGS ?= -DENABLE_ASAN=ON -DENABLE_NETWORK=OFF -DBUILD_TESTING=OFF -DCMAKE_BUILD_TYPE=RelWithDebInfo -DENABLE_PYTHON_BINDINGS=OFF

# -dict=$(FUZZ_DICT) 
fuzz: ensure-fuzz-dirs
	$(FUZZ_BIN) -close_fd_mask=3 -artifact_prefix=$(FUZZ_DIR)/artifacts/ -max_len=4096 -timeout=5 -ignore_crashes=1 -detect_leaks=1 $(FUZZ_ARGS) $(FUZZ_DIR)/corpus 2>&1 | tee $(FUZZ_DIR)/logs/fuzz.log

clean:
	rm -rf -- $(FUZZ_DIR)/*
	cd $(BUILD_DIR) && make clean

clean-fuzz: clean-fuzz-logs
	rm -rf $(FUZZ_DIR)/artifacts
	rm -rf $(FUZZ_DIR)/corpus

clean-fuzz-logs:
	rm -rf $(FUZZ_DIR)/logs

clean-build:
	rm -rf $(BUILD_DIR)/*

clean-coverage:
	rm -rf $(COV_DIR) $(FUZZ_DIR)/coverage_html lcov.info

coverage-run: coverage-build ensure-cov-dirs
	rm -f $(COV_DIR)/*.profraw
	LLVM_PROFILE_FILE=$(COV_DIR)/%m.profraw $(FUZZ_COV_BIN) -runs=0 -timeout=25 -close_fd_mask=3 $(FUZZ_DIR)/corpus

coverage: coverage-run
	$(LLVM_PROFDATA) merge -sparse $(COV_DIR)/*.profraw -o $(COV_PROFDATA) \
	&& $(LLVM_COV) export $(FUZZ_COV_BIN) -instr-profile=$(COV_PROFDATA) -format=lcov \
	   -ignore-filename-regex='$(COV_IGNORE_RE)' > lcov.info \
	&& $(LLVM_COV) show $(FUZZ_COV_BIN) \
	   -instr-profile=$(COV_PROFDATA) \
	   -format=html \
	   -output-dir=$(FUZZ_DIR)/coverage_html \
	   -show-line-counts \
	   -show-regions \
	   -ignore-filename-regex='$(COV_IGNORE_RE)' \
	   -Xdemangler=c++filt \
	&& $(LLVM_COV) report $(FUZZ_COV_BIN) -instr-profile=$(COV_PROFDATA)

fuzz-logs: ensure-fuzz-dirs
	find "$(FUZZ_DIR)/artifacts" -type f -print0 | \
		xargs -0 realpath -z | \
		xargs -0 -P "$(shell nproc --ignore=1)" -I{} bash -c '\
			f="$$1"; \
			BASENAME=$$(basename "$$f"); \
			log="$(FUZZ_DIR)/logs/$$BASENAME.log"; \
			if [ ! -s "$$log" ]; then \
				unset TC; \
				$(FUZZ_BIN) -timeout=600 "$$f" >"$$log" 2>&1; \
				echo "Processed $$f"; \
			fi \
		' _ "{}"

build: ensure-build-dirs
	cd $(BUILD_DIR) && CC=$(CC) CXX=$(CXX) cmake $(CMAKE_ARGS) ..
	cd $(BUILD_DIR) && make -j$(shell nproc)

build-clean: clean-build build

ensure-build-dirs:
	mkdir -p $(BUILD_DIR)

ensure-fuzz-dirs:
	mkdir -p $(FUZZ_DIR)/artifacts $(FUZZ_DIR)/corpus $(FUZZ_DIR)/logs

ensure-cov-dirs:
	mkdir -p $(COV_DIR)


