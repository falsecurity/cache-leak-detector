#------------------------------------------------------------------------
# Names, Directories, Includes
#------------------------------------------------------------------------

# Project Name
PROJ := Cache Leak Detector - Pintool

# Pintool Name
TEST_TOOL_ROOTS := instrcnt

# Pin Root
ifneq ($(MAKECMDGOALS),help)
    ifndef PIN_ROOT
        $(error PIN_ROOT is undefined!)
    endif
    CONFIG_ROOT := $(PIN_ROOT)/source/tools/Config
    include $(CONFIG_ROOT)/makefile.config
    include $(TOOLS_ROOT)/Config/makefile.default.rules
endif

#------------------------------------------------------------------------
# Main Targets
#------------------------------------------------------------------------
.PHONY: all

all: obj-intel64/$(TEST_TOOL_ROOTS).so

help:
	@echo
	@echo "$(PROJ)"
	@echo
	@echo "  make [all] ............. Compile the project."
	@echo "  make help .............. Show this text."
	@echo "  make clean ............. Clean up the project."
	@echo

