bin_PROGRAMS =
check_PROGRAMS =
noinst_PROGRAMS =
TESTS =
EXTRA_DIST =
CLEANFILES =
DISTCLEANFILES =
ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

EXTRA_DIST += COPYRIGHT
EXTRA_DIST += LICENSE
EXTRA_DIST += README.md

AM_CPPFLAGS = \
	-include $(top_builddir)/config.h \
	-I$(top_srcdir)/wdns
AM_CFLAGS = $(my_CFLAGS) \
	-I$(top_builddir)/wdns
AM_LDFLAGS =

USE_LCOV=@USE_LCOV@
LCOV=@LCOV@
GENHTML=@GENHTML@

clean-coverage:
	@if [ $(USE_LCOV) = yes ] ; then \
		$(LCOV) --directory . --zerocounters ; \
		echo "Removing coverage info files and generated $(abs_top_builddir)/coverage-html/ directory" ; \
		rm -rf all.coverage report.coverage ; \
		rm -rf $(abs_top_builddir)/coverage-html/ ; \
	else \
		echo "Code coverage not enabled at configuration time." ; \
		echo "Use: ./configure --with-coverage" ; \
fi

report-coverage:
	@if [ $(USE_LCOV) = yes ] ; then \
		$(LCOV) --capture --directory . --output-file all.coverage ; \
		$(LCOV) --remove all.coverage \
			$(abs_top_srcdir)/t/\* \
			/usr/include/\* \
			--output report.coverage ; \
		$(GENHTML) --legend -o $(abs_top_builddir)/coverage-html report.coverage ; \
		echo "Generated Code Coverage report in HTML at $(abs_top_builddir)/coverage-html" ; \
	else \
		echo "Code coverage not enabled at configuration time." ; \
		echo "Use: ./configure --with-coverage" ; \
fi

#
##
### library
##
#

LIBWDNS_CURRENT=2
LIBWDNS_REVISION=0
LIBWDNS_AGE=1

include_HEADERS = wdns/wdns.h
lib_LTLIBRARIES = wdns/libwdns.la

EXTRA_DIST += wdns/gen_rcode_to_str
EXTRA_DIST += wdns/gen_rrclass_to_str
EXTRA_DIST += wdns/gen_rrtype_to_str
DISTCLEANFILES += wdns/rrtype_to_str.c \
	wdns/rcode_to_str.c \
	wdns/rrclass_to_str.c

wdns/rcode_to_str.c: wdns/wdns.h wdns/gen_rcode_to_str
	$(PYTHON) $(top_srcdir)/wdns/gen_rcode_to_str wdns/wdns.h wdns/rcode_to_str.c

wdns/rrclass_to_str.c: wdns/wdns.h wdns/gen_rrclass_to_str
	$(PYTHON) $(top_srcdir)/wdns/gen_rrclass_to_str wdns/wdns.h wdns/rrclass_to_str.c

wdns/rrtype_to_str.c: wdns/wdns.h wdns/gen_rrtype_to_str
	$(PYTHON) $(top_srcdir)/wdns/gen_rrtype_to_str wdns/wdns.h wdns/rrtype_to_str.c

wdns_libwdns_la_CPPFLAGS = \
	-include $(top_builddir)/wdns/wdns-private.h
wdns_libwdns_la_LDFLAGS = $(AM_LDFLAGS) \
	-version-info $(LIBWDNS_CURRENT):$(LIBWDNS_REVISION):$(LIBWDNS_AGE)
if HAVE_LD_VERSION_SCRIPT
wdns_libwdns_la_LDFLAGS += \
	-Wl,--version-script=$(top_srcdir)/wdns/libwdns.sym
else
wdns_libwdns_la_LDFLAGS += \
	-export-symbols-regex "^(wdns_[a-z].*)"
endif
EXTRA_DIST += wdns/libwdns.sym
wdns_libwdns_la_SOURCES = \
	libmy/my_alloc.h \
	libmy/vector.h \
	libmy/ubuf.h \
	wdns/wdns-private.h \
	wdns/wdns.h \
	libmy/b32_decode.c \
	libmy/b32_decode.h \
	libmy/b32_encode.c \
	libmy/b32_encode.h \
	libmy/b64_decode.c \
	libmy/b64_decode.h \
	libmy/b64_encode.c \
	libmy/b64_encode.h \
	wdns/clear.c \
	wdns/compare_rr_rrset.c \
	wdns/copy_uname.c \
	wdns/count_labels.c \
	wdns/deserialize_rrset.c \
	wdns/domain_to_str.c \
	wdns/downcase_name.c \
	wdns/downcase_rdata.c \
	wdns/downcase_rrset.c \
	wdns/file_load_names.c \
	wdns/insert_rr_rrset_array.c \
	wdns/is_subdomain.c \
	wdns/left_chop.c \
	wdns/len_uname.c \
	wdns/message_to_str.c \
	wdns/parse_edns.c \
	wdns/parse_header.c \
	wdns/parse_message.c \
	wdns/parse_message_rr.c \
	wdns/parse_rdata.c \
	wdns/print_message.c \
	wdns/print_rr.c \
	wdns/print_rrset.c \
	wdns/print_rrset_array.c \
	wdns/opcode_to_str.c \
	wdns/rcode_to_str.c \
	wdns/rdata_to_str.c \
	wdns/rdata_to_ubuf.c \
	wdns/record_descr.c \
	wdns/record_descr.h \
	wdns/res_to_str.c \
	wdns/reverse_name.c \
	wdns/rr_to_str.c \
	wdns/rr_to_ubuf.c \
	wdns/rrclass_to_str.c \
	wdns/rrtype_to_str.c \
	wdns/rrset_array_to_str.c \
	wdns/rrset_array_to_ubuf.c \
	wdns/rrset_to_str.c \
	wdns/rrset_to_ubuf.c \
	wdns/serialize_rrset.c \
	wdns/sort_rrset.c \
	wdns/skip_name.c \
	wdns/str_to_name.c \
	wdns/str_to_rdata_ubuf.c \
	wdns/unpack_name.c \
	wdns/version.c

pkgconfig_DATA = wdns/libwdns.pc
EXTRA_DIST += wdns/libwdns.pc.in
CLEANFILES += wdns/libwdns.pc

noinst_PROGRAMS += examples/wdns-dump-file
examples_wdns_dump_file_LDADD = wdns/libwdns.la
examples_wdns_dump_file_SOURCES = \
	examples/private.h \
	examples/wdns-dump-file.c

if LIBPCAP
noinst_PROGRAMS += examples/wdns-dump-pcap
examples_wdns_dump_pcap_LDADD = wdns/libwdns.la -lpcap
examples_wdns_dump_pcap_SOURCES = \
	examples/private.h \
	examples/wdns-dump-pcap.c
endif

noinst_PROGRAMS += examples/wdns-print-version
examples_wdns_print_version_LDADD = wdns/libwdns.la
examples_wdns_print_version_SOURCES = \
	examples/private.h \
	examples/wdns-print-version.c

noinst_PROGRAMS += examples/wdns-test-deserialize-rrset
examples_wdns_test_deserialize_rrset_LDADD = wdns/libwdns.la
examples_wdns_test_deserialize_rrset_SOURCES = \
	examples/private.h \
	examples/wdns-hex-driver.c \
	examples/wdns-test-deserialize-rrset.c

noinst_PROGRAMS += examples/wdns-test-downcase-rrset
examples_wdns_test_downcase_rrset_LDADD = wdns/libwdns.la
examples_wdns_test_downcase_rrset_SOURCES = \
	examples/private.h \
	examples/wdns-hex-driver.c \
	examples/wdns-test-downcase-rrset.c

noinst_PROGRAMS += examples/wdns-test-print-message
examples_wdns_test_print_message_LDADD = wdns/libwdns.la
examples_wdns_test_print_message_SOURCES = \
	examples/private.h \
	examples/wdns-hex-driver.c \
	examples/wdns-test-print-message.c

noinst_PROGRAMS += examples/wdns-test-serialize-rrset
examples_wdns_test_serialize_rrset_LDADD = wdns/libwdns.la
examples_wdns_test_serialize_rrset_SOURCES = \
	examples/private.h \
	examples/wdns-hex-driver.c \
	examples/wdns-test-serialize-rrset.c

#
##
### tests
##
#

EXTRA_DIST += t/test-common.h

AM_TESTS_ENVIRONMENT = top_builddir='$(top_builddir)'; top_srcdir='$(top_srcdir)'; export top_builddir top_srcdir;
TESTS_ENVIRONMENT = $(AM_TESTS_ENVIRONMENT)

TESTS += t/test-name_to_str
check_PROGRAMS += t/test-name_to_str
t_test_name_to_str_SOURCES = t/test-name_to_str.c t/test-common.c
t_test_name_to_str_LDADD = wdns/libwdns.la

TESTS += t/test-str_to_name
check_PROGRAMS += t/test-str_to_name
t_test_str_to_name_SOURCES = t/test-str_to_name.c t/test-common.c
t_test_str_to_name_LDADD = wdns/libwdns.la

TESTS += t/test-str_to_rcode
check_PROGRAMS += t/test-str_to_rcode
t_test_str_to_rcode_SOURCES = t/test-str_to_rcode.c t/test-common.c
t_test_str_to_rcode_LDADD = wdns/libwdns.la

TESTS += t/test-str_to_rdata
check_PROGRAMS += t/test-str_to_rdata
t_test_str_to_rdata_SOURCES = t/test-str_to_rdata.c t/test-common.c
t_test_str_to_rdata_LDADD = wdns/libwdns.la

TESTS += t/test-rdata_to_str
check_PROGRAMS += t/test-rdata_to_str
t_test_rdata_to_str_SOURCES = t/test-rdata_to_str.c t/test-common.c
t_test_rdata_to_str_LDADD = wdns/libwdns.la

TESTS += t/test-str_to_rrtype
check_PROGRAMS += t/test-str_to_rrtype
t_test_str_to_rrtype_SOURCES = t/test-str_to_rrtype.c t/test-common.c
t_test_str_to_rrtype_LDADD = wdns/libwdns.la
