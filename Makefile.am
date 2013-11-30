bin_PROGRAMS =
check_PROGRAMS =
TESTS =
EXTRA_DIST =
CLEANFILES =
ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

AM_CPPFLAGS = \
	-include $(top_builddir)/config.h \
	-I$(top_srcdir)/wdns
AM_CFLAGS = $(my_CFLAGS)
AM_LDFLAGS = -Wl,--as-needed

EXTRA_DIST += COPYRIGHT

LIBWDNS_CURRENT=0
LIBWDNS_REVISION=0
LIBWDNS_AGE=0

include_HEADERS = wdns/wdns.h
lib_LTLIBRARIES = wdns/libwdns.la

EXTRA_DIST += wdns/gen_rrclass_to_str
EXTRA_DIST += wdns/gen_rrtype_to_str

wdns/rrclass_to_str.c: wdns/wdns.h wdns/gen_rrclass_to_str
	$(AM_V_GEN)wdns/gen_rrclass_to_str wdns/wdns.h wdns/rrclass_to_str.c

wdns/rrtype_to_str.c: wdns/wdns.h wdns/gen_rrtype_to_str
	$(AM_V_GEN)wdns/gen_rrtype_to_str wdns/wdns.h wdns/rrtype_to_str.c

wdns_libwdns_la_CPPFLAGS = \
	-include $(top_builddir)/wdns/wdns-private.h
wdns_libwdns_la_LDFLAGS = $(AM_LDFLAGS) \
	-version-info $(LIBWDNS_CURRENT):$(LIBWDNS_REVISION):$(LIBWDNS_AGE) \
	-export-symbols-regex "^(wdns_[a-z].*)"
wdns_libwdns_la_SOURCES = \
	libmy/my_alloc.h \
	libmy/vector.h \
	libmy/ubuf.h \
	wdns/wdns-private.h \
	wdns/wdns.h \
	wdns/b32_encode.c \
	wdns/b32_encode.h \
	wdns/b64_encode.c \
	wdns/b64_encode.h \
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
	wdns/unpack_name.c

pkgconfig_DATA = wdns/libwdns.pc
EXTRA_DIST += wdns/libwdns.pc.in
CLEANFILES += wdns/libwdns.pc

if LIBPCAP
bin_PROGRAMS += examples/wdns-dump-pcap
examples_wdns_dump_pcap_LDADD = wdns/libwdns.la -lpcap
examples_wdns_dump_pcap_SOURCES = \
	examples/private.h \
	examples/wdns-dump-pcap.c
endif

bin_PROGRAMS += examples/wdns-test-deserialize-rrset
examples_wdns_test_deserialize_rrset_LDADD = wdns/libwdns.la
examples_wdns_test_deserialize_rrset_SOURCES = \
	examples/private.h \
	examples/wdns-hex-driver.c \
	examples/wdns-test-deserialize-rrset.c

bin_PROGRAMS += examples/wdns-test-downcase-rrset
examples_wdns_test_downcase_rrset_LDADD = wdns/libwdns.la
examples_wdns_test_downcase_rrset_SOURCES = \
	examples/private.h \
	examples/wdns-hex-driver.c \
	examples/wdns-test-downcase-rrset.c

bin_PROGRAMS += examples/wdns-test-print-message
examples_wdns_test_print_message_LDADD = wdns/libwdns.la
examples_wdns_test_print_message_SOURCES = \
	examples/private.h \
	examples/wdns-hex-driver.c \
	examples/wdns-test-print-message.c

bin_PROGRAMS += examples/wdns-test-serialize-rrset
examples_wdns_test_serialize_rrset_LDADD = wdns/libwdns.la
examples_wdns_test_serialize_rrset_SOURCES = \
	examples/private.h \
	examples/wdns-hex-driver.c \
	examples/wdns-test-serialize-rrset.c
