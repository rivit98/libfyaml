LSAN_OPTIONS=
detect_odr_violation=0:abort_on_error=1:symbolize=0:allocator_may_return_null=1:
handle_segv=0:handle_sigbus=0:handle_abort=0:handle_sigfpe=0:handle_sigill=0:
detect_stack_use_after_return=0:check_initialization_order=0:


export LSAN_OPTIONS='symbolize=0:detect_leaks=1:malloc_context_size=30:print_suppressions=0'


ASAN_OPTIONS = UBSAN_OPTIONS = 
detect_odr_violation=0:abort_on_error=1:symbolize=0:allocator_may_return_null=1:
handle_segv=0:handle_sigbus=0:handle_abort=0:handle_sigfpe=0:handle_sigill=0:
detect_stack_use_after_return=0:check_initialization_order=0:

halt_on_error=1:detect_leaks=0:malloc_context_size=0:



MSAN_OPTIONS = 
detect_odr_violation=0:abort_on_error=1:symbolize=0:allocator_may_return_null=1:
handle_segv=0:handle_sigbus=0:handle_abort=0:handle_sigfpe=0:handle_sigill=0:
detect_stack_use_after_return=0:check_initialization_order=0:

halt_on_error=1:detect_leaks=0:malloc_context_size=0:exit_code=86:msan_track_origins=0: