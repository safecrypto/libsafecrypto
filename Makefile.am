ACLOCAL_AMFLAGS = -I m4 -I /usr/share/aclocal
include aminclude.am

if !WITH_BAREMETAL
MAYBE_BINDINGS=bindings
MAYBE_BUILD_TOOLS=build_tools
endif !WITH_BAREMETAL

SUBDIRS     = $(MAYBE_BUILD_TOOLS) . docs/Doxygen src $(MAYBE_BINDINGS) test

EXTRA_DIST  = docs/Resources/SAFEcrypto.png \
              docs/Resources/SAFEcrypto_small.png \
              docs/Resources/SAFEcrypto_structure.png \
              README.md \
              LICENSE \
              version

dist_bin_SCRIPTS = build_tools/ntt_table_gen/ntt_table_gen.sh \
                   setup_version.sh \
                   style_rules.sh \
                   style_info.sh

# Design documentation
DESIGN_DOC_TARGETS = 

if HAVE_PDFLATEX
if HAVE_DESIGN_DOC
docfiles = docs/coding.pdf docs/sad.pdf

coding_guidelines:
	cd docs/CodingGuidelines; make
	mv docs/CodingGuidelines/coding.pdf docs/coding.pdf

sad:
	cd docs/SAD; make
	mv docs/SAD/sad.pdf docs/sad.pdf

design-doc: coding_guidelines sad

design-doc-dist: design-doc-clean design-doc
	mv $(top_srcdir)/docs/sad.pdf $(distdir)/docs/sad.pdf
	mv $(top_srcdir)/docs/coding.pdf $(distdir)/docs/coding.pdf

DESIGN_DOC_TARGETS += design-doc-dist

design-doc-clean:
	cd docs/SAD; make clean
	cd docs/CodingGuidelines; make clean
	rm -rf $(docfiles)

endif HAVE_DESIGN_DOC
endif HAVE_PDFLATEX


# Style rules - must be conditionally enabled through the configure script
CODE_STYLE_RULES =
if HAVE_CODE_STYLE_RULES
style_rules:
	sh $(srcdir)/style_rules.sh $(distdir) src
	sh $(srcdir)/style_rules.sh $(distdir) include
	sh $(srcdir)/style_rules.sh $(distdir) examples
	sh $(srcdir)/style_rules.sh $(distdir) test

CODE_STYLE_RULES += style_rules
endif HAVE_CODE_STYLE_RULES

# Pass information from git to file headers in source distributions
style_info:
	sh $(srcdir)/style_info.sh $(distdir) src
	sh $(srcdir)/style_info.sh $(distdir) include
	sh $(srcdir)/style_info.sh $(distdir) examples
	sh $(srcdir)/style_info.sh $(distdir) test

# Create the version information header file
setup_version: version
	sh $(srcdir)/setup_version.sh version src/safecrypto_version.h

# Create the NTT tables source code
setup_ntt:
	sh $(srcdir)/build_tools/ntt_table_gen/ntt_table_gen.sh $(srcdir)/src/utils/arith/ntt_tables

all-local: setup_version setup_ntt
clean-local:
	rm -rf ./src/safecrypto_version.h

# Makefile targets that are called prior to generating the distribution
# compressed file are assigned here.
dist-hook: setup_version setup_ntt style_info $(DESIGN_DOC_TARGETS) $(CODE_STYLE_RULES)


if HAVE_SPLINT
splint_analysis:
	cd src; splint -help;

endif HAVE_SPLINT
