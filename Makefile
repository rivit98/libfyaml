
.PHONY: build build-clean fuzz clean coverage

FUZZ_ARGS?=-fork=1
FUZZ_DIR=$(shell realpath ../fuzz/libfyaml)
FUZZ_DICT=./src/fuzz/yaml.dict
BUILD_DIR=./build

# -dict=$(FUZZ_DICT) 
fuzz: ensure-fuzz-dirs
	LLVM_PROFILE_FILE=$(FUZZ_DIR)/default.profraw $(BUILD_DIR)/fuzz -close_fd_mask=3 -artifact_prefix=$(FUZZ_DIR)/artifacts/ -max_len=1024 -timeout=5 -ignore_crashes=1 -detect_leaks=1 $(FUZZ_ARGS) $(FUZZ_DIR)/corpus 2>&1 | tee $(FUZZ_DIR)/logs/fuzz.log

clean:
	rm -rf -- $(FUZZ_DIR)/*
	cd $(BUILD_DIR) && make clean

clean-fuzz:
	rm -rf $(FUZZ_DIR)/artifacts
	rm -rf $(FUZZ_DIR)/corpus
	rm -rf $(FUZZ_DIR)/logs

clean-fuzz-logs:
	rm -rf $(FUZZ_DIR)/logs

clean-build:
	rm -rf $(BUILD_DIR)/*

coverage:
	llvm-profdata merge -sparse $(FUZZ_DIR)/*.profraw -o $(FUZZ_DIR)/default.profdata \
	&& llvm-cov export $(BUILD_DIR)/fuzz -instr-profile=$(FUZZ_DIR)/default.profdata -format=lcov > lcov.info \
	&& llvm-cov show $(BUILD_DIR)/fuzz \
	   -instr-profile=$(FUZZ_DIR)/default.profdata \
	   -format=html \
	   -output-dir=$(FUZZ_DIR)/coverage_html \
	   -show-line-counts \
	   -show-regions \
	   -Xdemangler=c++filt \
	&& llvm-cov report $(BUILD_DIR)/fuzz -instr-profile=$(FUZZ_DIR)/default.profdata

fuzz-logs: ensure-fuzz-dirs
	find "$(FUZZ_DIR)/artifacts" -type f -print0 | \
		xargs -0 realpath -z | \
		xargs -0 -P "$(shell nproc --ignore=1)" -I{} bash -c '\
			f="$$1"; \
			BASENAME=$$(basename "$$f"); \
			log="$(FUZZ_DIR)/logs/$$BASENAME.log"; \
			[ ! -s "$$log" ] && \
			$(BUILD_DIR)/fuzz -timeout=600 "$$f" >"$$log" 2>&1 \
		' _ "{}"

build: ensure-build-dirs
	cd $(BUILD_DIR) && CC=clang CXX=clang++ cmake -DENABLE_ASAN=ON -DENABLE_NETWORK=OFF -DBUILD_TESTING=OFF -DCMAKE_BUILD_TYPE=RelWithDebInfo ..
	cd $(BUILD_DIR) && make -j$(shell nproc)

build-clean: clean-build build

ensure-build-dirs:
	mkdir -p $(BUILD_DIR)

ensure-fuzz-dirs:
	mkdir -p $(FUZZ_DIR)/artifacts $(FUZZ_DIR)/corpus $(FUZZ_DIR)/logs

