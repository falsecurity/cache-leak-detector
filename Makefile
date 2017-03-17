#------------------------------------------------------------------------
# Project Settings
#------------------------------------------------------------------------
PROJ := Cache Leak Detector - Example Project
PIN := pin
ifeq ($(MAKECMDGOALS),$(filter $(MAKECMDGOALS),all clean))
    ifeq ($(PIN_ROOT),)
        $(error "[ERROR] PIN_ROOT is not defined!")
    endif
endif
ifeq ($(MAKECMDGOALS),detect)
    loops := 10
endif

#------------------------------------------------------------------------
# Commands
#------------------------------------------------------------------------
MEAS := pin -injection child -t pintool/obj-intel64/instrcnt.so \
        -o example/instrcnt.bin -- ./target/bin/target \
        example/2048bit.key example/exponents.bin

CONV := ./report/tonumpy.py -k 2048 -o example/measurements.npz \
        example/instrcnt.bin example/exponents.bin

REP := ./report/report.py example/measurements.npz > example/report.txt

#------------------------------------------------------------------------
# Main Targets
#------------------------------------------------------------------------
.PHONY: all doc clean measure convert report detect

all:
	$(MAKE) -C target
	$(MAKE) -C pintool

clean:
	$(MAKE) clean -C target
	$(MAKE) clean -C pintool
	$(MAKE) clean -C doxygen

doc:
	$(MAKE) -C doxygen

measure:
	@if [ -n "$(loops)" ]; then \
		echo "Start: `date`"; \
		for i in `seq 1 $(loops)`; do `$(MEAS)`; done; \
		echo "End:   `date`"; \
	else \
		`$(MEAS)`; \
		echo "Done"; \
	fi

convert:
	`$(CONV)`

report:
	`$(REP)`

detect: measure convert report

help:
	@echo
	@echo "$(PROJ)"
	@echo
	@echo "  make [all] ............. Compile the project."
	@echo "  make help .............. Show this text."
	@echo "  make doc ............... Generate documentation."
	@echo "  make clean ............. Clean up the project."
	@echo "  make measure ........... Example measurement."
	@echo "  make measure loops= .... Example measurement in a loop."
	@echo "  make convert ........... Example numpy conversion."
	@echo "  make report ............ Example report generation."
	@echo "  make detect ............ Entire example run."
	@echo

