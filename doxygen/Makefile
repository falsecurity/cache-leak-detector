#------------------------------------------------------------------------
# Project Settings
#------------------------------------------------------------------------
PROJ := Cache Leak Detector - Documentation
BUILDDIR := html
DOXYFILE := Doxyfile
HTMLFILE := index.html

#------------------------------------------------------------------------
# Main Targets
#------------------------------------------------------------------------
.PHONY: all 

all:
	doxygen $(DOXYFILE)
	ln -sf $(BUILDDIR)/$(HTMLFILE) $(HTMLFILE)

clean:
	-$(RM) -r $(HTMLFILE) $(BUILDDIR)

help:
	@echo
	@echo "$(PROJ)"
	@echo
	@echo "  make [all] ............. Compile the project."
	@echo "  make help .............. Show this text."
	@echo "  make clean ............. Clean up the project."
	@echo

