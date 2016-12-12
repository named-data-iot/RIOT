/*
 * Copyright (C) 2016 Wentao Shang <wentaoshang@gmail.com>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @{
 *
 * @file
 */
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "embUnit.h"

#include "hashes/sha256.h"
#include "ndn-riot/encoding/ndn-constants.h"
#include "ndn-riot/encoding/block.h"
#include "ndn-riot/encoding/name.h"
#include "ndn-riot/encoding/interest.h"
#include "ndn-riot/encoding/metainfo.h"
#include "ndn-riot/encoding/data.h"
#include "random.h"
#include "uECC.h"

#include "unittests-constants.h"
#include "tests-ndn_encoding.h"

static void set_up(void)
{
    gnrc_pktbuf_init();
    random_init(0);
}

/* tests for block.h */

static void test_ndn_block_get_var_number__invalid(void)
{
    uint8_t buf[9] = {0x11, 253, 0x12, 0x34, 254, 0x11, 0x22, 0x33, 0x44};
    uint32_t num;
    TEST_ASSERT_EQUAL_INT(-1, ndn_block_get_var_number(NULL, sizeof(buf), &num));
    TEST_ASSERT_EQUAL_INT(-1, ndn_block_get_var_number(buf, 0, &num));
    TEST_ASSERT_EQUAL_INT(-1, ndn_block_get_var_number(buf, sizeof(buf), NULL));
}

static void test_ndn_block_get_var_number__valid(void)
{
    uint8_t buf[9] = {0x11, 253, 0x12, 0x34, 254, 0x11, 0x22, 0x33, 0x44};
    uint32_t num = 0;
    TEST_ASSERT_EQUAL_INT(1, ndn_block_get_var_number(buf, sizeof(buf), &num));
    TEST_ASSERT_EQUAL_INT(0x11, num);

    TEST_ASSERT_EQUAL_INT(3, ndn_block_get_var_number(buf + 1, sizeof(buf) - 1, &num));
    TEST_ASSERT_EQUAL_INT(0x1234, num);

    TEST_ASSERT_EQUAL_INT(5, ndn_block_get_var_number(buf + 4, sizeof(buf) - 4, &num));
    TEST_ASSERT_EQUAL_INT(0x11223344, num);
}

static void test_ndn_block_put_var_number__invalid(void)
{
    uint8_t buf[4];
    TEST_ASSERT_EQUAL_INT(-1, ndn_block_put_var_number(1, NULL, sizeof(buf)));
    TEST_ASSERT_EQUAL_INT(-1, ndn_block_put_var_number(1, buf, 0));
    TEST_ASSERT_EQUAL_INT(-1, ndn_block_put_var_number(1, buf, -1));
}

static void test_ndn_block_put_var_number__valid(void)
{
    uint8_t buf[5];
    TEST_ASSERT_EQUAL_INT(1, ndn_block_put_var_number(1, buf, sizeof(buf)));
    TEST_ASSERT_EQUAL_INT(1, buf[0]);

    TEST_ASSERT_EQUAL_INT(3, ndn_block_put_var_number(0x1234, buf, sizeof(buf)));
    TEST_ASSERT_EQUAL_INT(253, buf[0]);
    TEST_ASSERT_EQUAL_INT(0x12, buf[1]);
    TEST_ASSERT_EQUAL_INT(0x34, buf[2]);

    TEST_ASSERT_EQUAL_INT(5, ndn_block_put_var_number(0x11223344, buf, sizeof(buf)));
    TEST_ASSERT_EQUAL_INT(254, buf[0]);
    TEST_ASSERT_EQUAL_INT(0x11, buf[1]);
    TEST_ASSERT_EQUAL_INT(0x22, buf[2]);
    TEST_ASSERT_EQUAL_INT(0x33, buf[3]);
    TEST_ASSERT_EQUAL_INT(0x44, buf[4]);
}

static void test_ndn_block_var_number_length__all(void)
{
    TEST_ASSERT_EQUAL_INT(1, ndn_block_var_number_length(1));
    TEST_ASSERT_EQUAL_INT(3, ndn_block_var_number_length(253));
    TEST_ASSERT_EQUAL_INT(3, ndn_block_var_number_length(254));
    TEST_ASSERT_EQUAL_INT(3, ndn_block_var_number_length(255));
    TEST_ASSERT_EQUAL_INT(3, ndn_block_var_number_length(0x100));
    TEST_ASSERT_EQUAL_INT(5, ndn_block_var_number_length(0x10000));
}

static void test_ndn_block_total_length__all(void)
{
    TEST_ASSERT_EQUAL_INT(4, ndn_block_total_length(1, 2));
    TEST_ASSERT_EQUAL_INT(2, ndn_block_total_length(1, 0));
}

static void test_ndn_block_integer_length__all(void)
{
    TEST_ASSERT_EQUAL_INT(1, ndn_block_integer_length(1));
    TEST_ASSERT_EQUAL_INT(2, ndn_block_integer_length(0x100));
    TEST_ASSERT_EQUAL_INT(4, ndn_block_integer_length(0x10000));
}

static void test_ndn_block_put_integer__invalid(void)
{
    uint8_t buf[4] = {0, 0, 0, 0};
    TEST_ASSERT_EQUAL_INT(-1, ndn_block_put_integer(1, NULL, 0));
    TEST_ASSERT_EQUAL_INT(-1, ndn_block_put_integer(1, buf, -1));
    TEST_ASSERT_EQUAL_INT(-1, ndn_block_put_integer(0x11, buf, 0));
    TEST_ASSERT_EQUAL_INT(-1, ndn_block_put_integer(0x1111, buf, 1));
    TEST_ASSERT_EQUAL_INT(-1, ndn_block_put_integer(0x111111, buf, 2));
}

static void test_ndn_block_put_integer__valid(void)
{
    uint8_t buf[4] = {0, 0, 0, 0};
    TEST_ASSERT_EQUAL_INT(1, ndn_block_put_integer(1, buf, sizeof(buf)));
    TEST_ASSERT_EQUAL_INT(1, buf[0]);
    TEST_ASSERT_EQUAL_INT(2, ndn_block_put_integer(0x7890, buf, sizeof(buf)));
    TEST_ASSERT_EQUAL_INT(0x78, buf[0]);
    TEST_ASSERT_EQUAL_INT(0x90, buf[1]);
    TEST_ASSERT_EQUAL_INT(4, ndn_block_put_integer(0x789015, buf, sizeof(buf)));
    TEST_ASSERT_EQUAL_INT(0, buf[0]);
    TEST_ASSERT_EQUAL_INT(0x78, buf[1]);
    TEST_ASSERT_EQUAL_INT(0x90, buf[2]);
    TEST_ASSERT_EQUAL_INT(0x15, buf[3]);
}

static void test_ndn_block_from_packet__invalid(void)
{
    ndn_block_t block;

    uint8_t buf1[] = {NDN_TLV_INTEREST, 100};
    gnrc_pktsnip_t* pkt1 = gnrc_pktbuf_add(NULL, buf1, sizeof(buf1),
					   GNRC_NETTYPE_UNDEF);
    gnrc_pktsnip_t* pkt2 = gnrc_pktbuf_add(NULL, buf1, sizeof(buf1),
					   GNRC_NETTYPE_NDN);
    TEST_ASSERT_EQUAL_INT(-1, ndn_block_from_packet(NULL, &block));
    TEST_ASSERT_EQUAL_INT(-1, ndn_block_from_packet(pkt1, NULL));
    TEST_ASSERT_EQUAL_INT(-1, ndn_block_from_packet(pkt1, &block));
    TEST_ASSERT_EQUAL_INT(-1, ndn_block_from_packet(pkt2, &block));

    uint8_t buf2[]  = {NDN_TLV_SELECTORS, 100, NDN_TLV_NAME, 10};
    gnrc_pktsnip_t* pkt3 = gnrc_pktbuf_add(NULL, buf2, sizeof(buf2),
					   GNRC_NETTYPE_NDN);
    TEST_ASSERT_EQUAL_INT(-1, ndn_block_from_packet(pkt3, &block));
}

static void test_ndn_block_from_packet__valid(void)
{
    ndn_block_t block;

    uint8_t buf[] = {
	NDN_TLV_INTEREST, 26,
	NDN_TLV_NAME, 14,
	NDN_TLV_NAME_COMPONENT, 1, 'a',
	NDN_TLV_NAME_COMPONENT, 1, 'b',
	NDN_TLV_NAME_COMPONENT, 2, 'c', 'd',
	NDN_TLV_NAME_COMPONENT, 2, 'e', 'f',
    	NDN_TLV_NONCE, 4,
	0x76, 0x54, 0x32, 0x10,
    	NDN_TLV_INTERESTLIFETIME, 2, 0x40, 0,
    };
    gnrc_pktsnip_t* pkt = gnrc_pktbuf_add(NULL, buf, sizeof(buf),
					  GNRC_NETTYPE_NDN);
    TEST_ASSERT_EQUAL_INT(0, ndn_block_from_packet(pkt, &block));
    TEST_ASSERT((uint8_t*)pkt->data == block.buf);
    TEST_ASSERT_EQUAL_INT(gnrc_pkt_len(pkt), block.len);
}


Test *tests_ndn_encoding_block_tests(void)
{
    EMB_UNIT_TESTFIXTURES(fixtures) {
	new_TestFixture(test_ndn_block_get_var_number__invalid),
	new_TestFixture(test_ndn_block_get_var_number__valid),
	new_TestFixture(test_ndn_block_put_var_number__invalid),
	new_TestFixture(test_ndn_block_put_var_number__valid),
	new_TestFixture(test_ndn_block_var_number_length__all),
        new_TestFixture(test_ndn_block_integer_length__all),
        new_TestFixture(test_ndn_block_total_length__all),
        new_TestFixture(test_ndn_block_put_integer__invalid),
        new_TestFixture(test_ndn_block_put_integer__valid),
        new_TestFixture(test_ndn_block_from_packet__invalid),
        new_TestFixture(test_ndn_block_from_packet__valid),
    };

    EMB_UNIT_TESTCALLER(ndn_encoding_block_tests, set_up, NULL, fixtures);

    return (Test *)&ndn_encoding_block_tests;
}


/* tests for name.h */

static void test_ndn_name_component_compare__invalid(void)
{
    uint8_t buf[4] = {'a', 'b', 'c', 'd'};
    ndn_name_component_t good = { buf,  4 };
    ndn_name_component_t bad  = { NULL, 4 };
    TEST_ASSERT_EQUAL_INT(-2, ndn_name_component_compare(NULL, NULL));
    TEST_ASSERT_EQUAL_INT(-2, ndn_name_component_compare(NULL, &good));
    TEST_ASSERT_EQUAL_INT(-2, ndn_name_component_compare(&good, NULL));
    TEST_ASSERT_EQUAL_INT(-2, ndn_name_component_compare(&good, &bad));
    TEST_ASSERT_EQUAL_INT(-2, ndn_name_component_compare(&bad, &good));
}

static void test_ndn_name_component_compare__valid(void)
{
    uint8_t buf1[4] = {'a', 'b', 'c', 'd'};
    uint8_t buf2[4] = {'a', 'b', 'c', 'e'};
    uint8_t buf3[3] = {'a', 'b', 'c'};
    uint8_t buf4[3] = {'a', 'b', 'c'};
    ndn_name_component_t comp1 = { buf1, sizeof(buf1) };
    ndn_name_component_t comp2 = { buf2, sizeof(buf2) };
    ndn_name_component_t comp3 = { buf3, sizeof(buf3) };
    ndn_name_component_t comp4 = { buf4, sizeof(buf4) };
    ndn_name_component_t comp0 = { NULL, 0 };

    TEST_ASSERT_EQUAL_INT(-1, ndn_name_component_compare(&comp1, &comp2));
    TEST_ASSERT_EQUAL_INT( 1, ndn_name_component_compare(&comp2, &comp1));
    TEST_ASSERT_EQUAL_INT(-1, ndn_name_component_compare(&comp3, &comp2));
    TEST_ASSERT_EQUAL_INT( 0, ndn_name_component_compare(&comp3, &comp4));
    TEST_ASSERT_EQUAL_INT( 1, ndn_name_component_compare(&comp1, &comp0));
    TEST_ASSERT_EQUAL_INT( 0, ndn_name_component_compare(&comp0, &comp0));
    TEST_ASSERT_EQUAL_INT(-1, ndn_name_component_compare(&comp0, &comp1));
}

static void test_ndn_name_component_wire_encode__invalid(void)
{
    uint8_t src[4] = {'a', 'b', 'c', 'd'};
    uint8_t dst[4] = {0, 0, 0, 0};
    ndn_name_component_t comp = { src, sizeof(src) };
    ndn_name_component_t bad = { src, -4 };
    TEST_ASSERT_EQUAL_INT(-1, ndn_name_component_wire_encode(NULL, NULL, 0));
    TEST_ASSERT_EQUAL_INT(-1, ndn_name_component_wire_encode(&comp, NULL, 0));
    TEST_ASSERT_EQUAL_INT(-1, ndn_name_component_wire_encode(NULL, dst, sizeof(dst)));
    TEST_ASSERT_EQUAL_INT(-1, ndn_name_component_wire_encode(&bad, dst, sizeof(dst)));
    TEST_ASSERT_EQUAL_INT(-1, ndn_name_component_wire_encode(&comp, dst, -1));
}

static void test_ndn_name_component_wire_encode__valid(void)
{
    uint8_t src[4] = {'a', 'b', 'c', 'd'};
    uint8_t dst[6] = {0, 0, 0, 0, 0, 0};
    uint8_t result[6] = {NDN_TLV_NAME_COMPONENT, sizeof(src), 'a', 'b', 'c', 'd'};
    ndn_name_component_t comp = { src, sizeof(src) };
    TEST_ASSERT_EQUAL_INT(-1, ndn_name_component_wire_encode(&comp, dst, sizeof(dst) - 1));
    TEST_ASSERT_EQUAL_INT(sizeof(result), ndn_name_component_wire_encode(&comp, dst, sizeof(dst)));
    TEST_ASSERT_EQUAL_INT(0, memcmp(result, dst, sizeof(dst)));

    ndn_name_component_t empty = { NULL, 0 };
    TEST_ASSERT_EQUAL_INT(0, ndn_name_component_wire_encode(&empty, dst, sizeof(dst)));
}

static void test_ndn_name_compare__invalid(void)
{
    uint8_t buf[5] = {'a', 'b', 'c', 'd', 'e'};
    ndn_name_component_t comps1[4] = {
	{ buf, 1 },
	{ buf + 1, 1 },
	{ buf + 2, 1 },
	{ buf + 3, 1 }
    };
    ndn_name_t name1 = { 4, comps1 };  // URI = /a/b/c/d
    ndn_name_t bad = { 4, NULL };

    TEST_ASSERT_EQUAL_INT(-2, ndn_name_compare(NULL, NULL));
    TEST_ASSERT_EQUAL_INT(-2, ndn_name_compare(NULL, &name1));
    TEST_ASSERT_EQUAL_INT(-2, ndn_name_compare(&name1, NULL));
    TEST_ASSERT_EQUAL_INT(-2, ndn_name_compare(&name1, &bad));
    TEST_ASSERT_EQUAL_INT(-2, ndn_name_compare(&bad, &name1));
}

static void test_ndn_name_compare__valid(void)
{
    uint8_t buf[5] = {'a', 'b', 'c', 'd', 'e'};
    ndn_name_component_t comps1[4] = {
	{ buf, 1 },
	{ buf + 1, 1 },
	{ buf + 2, 1 },
	{ buf + 3, 1 }
    };
    ndn_name_t name1 = { 4, comps1 };  // URI = /a/b/c/d
    ndn_name_component_t comps2[4] = {
	{ buf, 1 },
	{ buf + 1, 1 },
	{ buf + 2, 1 },
	{ buf + 4, 1 }
    };
    ndn_name_t name2 = { 4, comps2 };  // URI = /a/b/c/e
    ndn_name_component_t comps3[3] = {
	{ buf, 1 },
	{ buf + 1, 1 },
	{ buf + 2, 1 }
    };
    ndn_name_t name3 = { 3, comps3 };  // URI = /a/b/c
    ndn_name_t name4 = { 4, comps1 };  // URI = /a/b/c/d
    ndn_name_component_t comps4[3] = {
	{ buf, 1 },
	{ buf + 1, 1 },
	{ buf + 3, 1 },
    };
    ndn_name_t name5 = { 3, comps4 };  // URI = /a/b/d
    ndn_name_t empty = { 0, NULL };

    // empty < name3 < name1 = name4 < name2 < name5

    TEST_ASSERT_EQUAL_INT(-1, ndn_name_compare(&empty, &name3));
    TEST_ASSERT_EQUAL_INT(1, ndn_name_compare(&name3, &empty));

    TEST_ASSERT_EQUAL_INT(0, ndn_name_compare(&name1, &name4));

    TEST_ASSERT_EQUAL_INT(-1, ndn_name_compare(&name1, &name2));
    TEST_ASSERT_EQUAL_INT(1, ndn_name_compare(&name2, &name1));

    TEST_ASSERT_EQUAL_INT(1, ndn_name_compare(&name4, &name3));
    TEST_ASSERT_EQUAL_INT(-1, ndn_name_compare(&name3, &name4));

    TEST_ASSERT_EQUAL_INT(1, ndn_name_compare(&name5, &name2));
    TEST_ASSERT_EQUAL_INT(-1, ndn_name_compare(&name2, &name5));
}

static void test_ndn_name_get_component__invalid(void)
{
    uint8_t buf[4] = "abcd";
    ndn_name_component_t comps1[4] = {
	{ buf, 1 },
	{ buf + 1, 1 },
	{ buf + 2, 1 },
	{ buf + 3, 1 }
    };
    ndn_name_t name1 = { 4, comps1 };  // URI = /a/b/c/d
    ndn_name_component_t dst;
    ndn_name_t empty = { 0, NULL };

    TEST_ASSERT_EQUAL_INT(-1, ndn_name_get_component(&empty, 0, &dst));
    TEST_ASSERT_EQUAL_INT(-1, ndn_name_get_component(NULL, 0, NULL));
    TEST_ASSERT_EQUAL_INT(-1, ndn_name_get_component(NULL, 0, &dst));
    TEST_ASSERT_EQUAL_INT(-1, ndn_name_get_component(&name1, 0, NULL));
    TEST_ASSERT_EQUAL_INT(-1, ndn_name_get_component(&name1, name1.size, &dst));
    TEST_ASSERT_EQUAL_INT(-1, ndn_name_get_component(&name1, name1.size + 1, &dst));
    TEST_ASSERT_EQUAL_INT(-1, ndn_name_get_component(&name1, -1 * (name1.size + 1), &dst));
}

static void test_ndn_name_get_component__valid(void)
{
    uint8_t buf[4] = "abcd";
    ndn_name_component_t comps1[4] = {
	{ buf, 1 },
	{ buf + 1, 1 },
	{ buf + 2, 1 },
	{ buf + 3, 1 }
    };
    ndn_name_t name1 = { 4, comps1 };  // URI = /a/b/c/d
    ndn_name_component_t dst;

    TEST_ASSERT_EQUAL_INT(0, ndn_name_get_component(&name1, 0, &dst));
    TEST_ASSERT(dst.buf == buf);
    TEST_ASSERT_EQUAL_INT(1, dst.len);
    TEST_ASSERT_EQUAL_INT(0, ndn_name_get_component(&name1, 1, &dst));
    TEST_ASSERT(dst.buf == buf + 1);
    TEST_ASSERT_EQUAL_INT(1, dst.len);
    TEST_ASSERT_EQUAL_INT(0, ndn_name_get_component(&name1, -1, &dst));
    TEST_ASSERT(dst.buf == buf + 3);
    TEST_ASSERT_EQUAL_INT(1, dst.len);
    TEST_ASSERT_EQUAL_INT(0, ndn_name_get_component(&name1, -1 * name1.size, &dst));
    TEST_ASSERT(dst.buf == buf);
    TEST_ASSERT_EQUAL_INT(1, dst.len);
}

static void test_ndn_name_total_length__invalid(void)
{
    uint8_t buf[8] = "abcd";
    ndn_name_component_t comps[4] = {
	{ buf, 4 },
	{ buf, -1 },
	{ NULL, 1 },
	{ buf, 0 },
    };
    ndn_name_t bad1 = { 1, comps + 1 };
    ndn_name_t bad2 = { 1, comps + 2 };
    ndn_name_t bad3 = { 1, comps + 3 };

    TEST_ASSERT_EQUAL_INT(-1, ndn_name_total_length(NULL));
    TEST_ASSERT_EQUAL_INT(-1, ndn_name_total_length(&bad1));
    TEST_ASSERT_EQUAL_INT(-1, ndn_name_total_length(&bad2));
    TEST_ASSERT_EQUAL_INT(-1, ndn_name_total_length(&bad3));
}

static void test_ndn_name_total_length__valid(void)
{
    uint8_t buf[6] = "abcdef";
    ndn_name_component_t comps1[4] = {
	{ buf, 1 },
	{ buf + 1, 1 },
	{ buf + 2, 2 },
	{ buf + 4, 2 }
    };
    ndn_name_t name1 = { 4, comps1 };  // URI = /a/b/cd/ef
    ndn_name_t empty = { 0, NULL };

    TEST_ASSERT_EQUAL_INT(16, ndn_name_total_length(&name1));
    TEST_ASSERT_EQUAL_INT(2, ndn_name_total_length(&empty));
}

static void test_ndn_name_wire_encode__invalid(void)
{
    uint8_t buf[8] = "abcd";
    ndn_name_component_t comps[4] = {
	{ buf, 4 },
	{ buf, -1 },
	{ NULL, 1 },
	{ buf, 0 },
    };
    ndn_name_t good = { 1, comps };
    ndn_name_t bad1 = { 1, comps + 1 };
    ndn_name_t bad2 = { 1, comps + 2 };
    ndn_name_t bad3 = { 1, comps + 3 };

    TEST_ASSERT_EQUAL_INT(-1, ndn_name_wire_encode(NULL, buf, 4));
    TEST_ASSERT_EQUAL_INT(-1, ndn_name_wire_encode(&good, NULL, 4));
    TEST_ASSERT_EQUAL_INT(-1, ndn_name_wire_encode(&good, buf, -1));
    TEST_ASSERT_EQUAL_INT(-1, ndn_name_wire_encode(&good, buf, 0));
    TEST_ASSERT_EQUAL_INT(-1, ndn_name_wire_encode(&bad1, buf, sizeof(buf)));
    TEST_ASSERT_EQUAL_INT(-1, ndn_name_wire_encode(&bad2, buf, sizeof(buf)));
    TEST_ASSERT_EQUAL_INT(-1, ndn_name_wire_encode(&bad3, buf, sizeof(buf)));
}

static void test_ndn_name_wire_encode__valid(void)
{
    uint8_t buf[6] = "abcdef";
    ndn_name_component_t comps1[4] = {
	{ buf, 1 },
	{ buf + 1, 1 },
	{ buf + 2, 2 },
	{ buf + 4, 2 }
    };
    ndn_name_t name1 = { 4, comps1 };  // URI = /a/b/cd/ef
    uint8_t dst[16];
    memset(dst, 0, sizeof(dst));
    uint8_t result[16] = {
	NDN_TLV_NAME, 14,
	NDN_TLV_NAME_COMPONENT, 1, 'a',
	NDN_TLV_NAME_COMPONENT, 1, 'b',
	NDN_TLV_NAME_COMPONENT, 2, 'c', 'd',
	NDN_TLV_NAME_COMPONENT, 2, 'e', 'f',
    };

    TEST_ASSERT_EQUAL_INT(sizeof(result), ndn_name_wire_encode(&name1, dst, sizeof(dst)));
    TEST_ASSERT(0 == memcmp(result, dst, sizeof(result)));

    ndn_name_t empty = { 0, NULL };
    uint8_t em_res[] = { NDN_TLV_NAME, 0, };
    TEST_ASSERT_EQUAL_INT(sizeof(em_res), ndn_name_wire_encode(&empty, dst, sizeof(dst)));
    TEST_ASSERT(0 == memcmp(em_res, dst, sizeof(em_res)));
}

static void test_ndn_name_from_uri__invalid(void)
{
    TEST_ASSERT_NULL(ndn_name_from_uri(NULL, 0));

    const char* str0 = "";
    TEST_ASSERT_NULL(ndn_name_from_uri(str0, 0));
    TEST_ASSERT_NULL(ndn_name_from_uri(str0, -1));

    const char* str1 = "aaa";
    TEST_ASSERT_NULL(ndn_name_from_uri(str1, strlen(str1)));

    const char* str2 = "//a";
    TEST_ASSERT_NULL(ndn_name_from_uri(str2, strlen(str2)));

    const char* str3 = "/a//";
    TEST_ASSERT_NULL(ndn_name_from_uri(str3, strlen(str3)));

    const char* str4 = "/a//b";
    TEST_ASSERT_NULL(ndn_name_from_uri(str4, strlen(str4)));

    const char* str5 = "/a/%";
    TEST_ASSERT_NULL(ndn_name_from_uri(str5, strlen(str5)));

    const char* str6 = "/a/%F";
    TEST_ASSERT_NULL(ndn_name_from_uri(str6, strlen(str6)));

    const char* str7 = "/a/%%";
    TEST_ASSERT_NULL(ndn_name_from_uri(str7, strlen(str7)));

    const char* str8 = "/a/%TS";
    TEST_ASSERT_NULL(ndn_name_from_uri(str8, strlen(str8)));
}

static void test_ndn_name_from_uri__valid(void)
{
    ndn_shared_block_t* shared = NULL;

    const char* str0 = "/";
    uint8_t res0[] = {
	NDN_TLV_NAME, 0,
    };
    shared = ndn_name_from_uri(str0, strlen(str0));
    TEST_ASSERT_NOT_NULL(shared);
    TEST_ASSERT_EQUAL_INT(sizeof(res0), shared->block.len);
    TEST_ASSERT(0 == memcmp(res0, shared->block.buf, sizeof(res0)));
    ndn_shared_block_release(shared);

    const char* str1 = "/a/b/c";
    uint8_t res1[] = {
	NDN_TLV_NAME, 9,
	NDN_TLV_NAME_COMPONENT, 1, 'a',
	NDN_TLV_NAME_COMPONENT, 1, 'b',
	NDN_TLV_NAME_COMPONENT, 1, 'c',
    };
    shared = ndn_name_from_uri(str1, strlen(str1));
    TEST_ASSERT_NOT_NULL(shared);
    TEST_ASSERT_EQUAL_INT(sizeof(res1), shared->block.len);
    TEST_ASSERT(0 == memcmp(res1, shared->block.buf, sizeof(res1)));
    ndn_shared_block_release(shared);

    const char* str2 = "/a/b/c/";
    uint8_t res2[] = {
	NDN_TLV_NAME, 9,
	NDN_TLV_NAME_COMPONENT, 1, 'a',
	NDN_TLV_NAME_COMPONENT, 1, 'b',
	NDN_TLV_NAME_COMPONENT, 1, 'c',
    };
    shared = ndn_name_from_uri(str2, strlen(str2));
    TEST_ASSERT_NOT_NULL(shared);
    TEST_ASSERT_EQUAL_INT(sizeof(res2), shared->block.len);
    TEST_ASSERT(0 == memcmp(res2, shared->block.buf, sizeof(res2)));
    ndn_shared_block_release(shared);

    const char* str3 = "/a/b/cd";
    uint8_t res3[] = {
	NDN_TLV_NAME, 10,
	NDN_TLV_NAME_COMPONENT, 1, 'a',
	NDN_TLV_NAME_COMPONENT, 1, 'b',
	NDN_TLV_NAME_COMPONENT, 2, 'c', 'd',
    };
    shared = ndn_name_from_uri(str3, strlen(str3));
    TEST_ASSERT_NOT_NULL(shared);
    TEST_ASSERT_EQUAL_INT(sizeof(res3), shared->block.len);
    TEST_ASSERT(0 == memcmp(res3, shared->block.buf, sizeof(res3)));
    ndn_shared_block_release(shared);

    const char* str4 = "/a/b/c/%FE%00%02%31";
    uint8_t res4[] = {
	NDN_TLV_NAME, 15,
	NDN_TLV_NAME_COMPONENT, 1, 'a',
	NDN_TLV_NAME_COMPONENT, 1, 'b',
	NDN_TLV_NAME_COMPONENT, 1, 'c',
	NDN_TLV_NAME_COMPONENT, 4, 0xFE, 0x00, 0x02, 0x31,
    };
    shared = ndn_name_from_uri(str4, strlen(str4));
    TEST_ASSERT_NOT_NULL(shared);
    TEST_ASSERT_EQUAL_INT(sizeof(res4), shared->block.len);
    TEST_ASSERT(0 == memcmp(res4, shared->block.buf, sizeof(res4)));
    ndn_shared_block_release(shared);

    const char* str5 = "/a/b/c/FE%00%02aa";
    uint8_t res5[] = {
	NDN_TLV_NAME, 17,
	NDN_TLV_NAME_COMPONENT, 1, 'a',
	NDN_TLV_NAME_COMPONENT, 1, 'b',
	NDN_TLV_NAME_COMPONENT, 1, 'c',
	NDN_TLV_NAME_COMPONENT, 6, 'F', 'E', 0x00, 0x02, 'a', 'a',
    };
    shared = ndn_name_from_uri(str5, strlen(str5));
    TEST_ASSERT_NOT_NULL(shared);
    TEST_ASSERT_EQUAL_INT(sizeof(res5), shared->block.len);
    TEST_ASSERT(0 == memcmp(res5, shared->block.buf, sizeof(res5)));
    ndn_shared_block_release(shared);

    char str6[500] = {0};
    str6[0] = '/';
    for (int i = 1; i < 497; ++i)
	str6[i] = 'a';
    str6[497] = '/';
    str6[498] = 'b';
    str6[499] = 0;
    uint8_t res6[507] = {0};
    res6[0] = NDN_TLV_NAME;
    res6[1] = 253;
    res6[2] = 0x01;
    res6[3] = 0xF7;
    res6[4] = NDN_TLV_NAME_COMPONENT;
    res6[5] = 253;
    res6[6] = 0x01;
    res6[7] = 0xF0;
    for (int i = 8; i < 504; ++i)
	res6[i] = 'a';
    res6[504] = NDN_TLV_NAME_COMPONENT;
    res6[505] = 1;
    res6[506] = 'b';
    shared = ndn_name_from_uri(str6, strlen(str6));
    TEST_ASSERT_NOT_NULL(shared);
    TEST_ASSERT_EQUAL_INT(sizeof(res6), shared->block.len);
    TEST_ASSERT(0 == memcmp(res6, shared->block.buf, sizeof(res6)));
    ndn_shared_block_release(shared);
}

static void test_ndn_name_append__all(void)
{
    uint8_t name[] = {
	NDN_TLV_NAME, 9,
	NDN_TLV_NAME_COMPONENT, 1, 'a',
	NDN_TLV_NAME_COMPONENT, 1, 'b',
	NDN_TLV_NAME_COMPONENT, 1, 'c',
    };
    uint8_t buf[] = {
	0xFE, 0x00, 0x02, 0x31,
    };
    uint8_t res[] = {
	NDN_TLV_NAME, 15,
	NDN_TLV_NAME_COMPONENT, 1, 'a',
	NDN_TLV_NAME_COMPONENT, 1, 'b',
	NDN_TLV_NAME_COMPONENT, 1, 'c',
	NDN_TLV_NAME_COMPONENT, 4, 0xFE, 0x00, 0x02, 0x31,
    };
    ndn_block_t nb = { name, sizeof(name) };

    ndn_shared_block_t* shared = ndn_name_append(&nb, buf, sizeof(buf));
    TEST_ASSERT_NOT_NULL(shared);
    TEST_ASSERT_EQUAL_INT(sizeof(res), shared->block.len);
    TEST_ASSERT(0 == memcmp(res, shared->block.buf, sizeof(res)));
    ndn_shared_block_release(shared);

    uint8_t buf2[500];
    memset(buf2, 'd', sizeof(buf2));
    uint8_t res2[517];
    res2[0] = NDN_TLV_NAME;
    res2[1] = 253;
    res2[2] = 0x02;
    res2[3] = 0x01;
    res2[4] = NDN_TLV_NAME_COMPONENT;
    res2[5] = 1;
    res2[6] = 'a';
    res2[7] = NDN_TLV_NAME_COMPONENT;
    res2[8] = 1;
    res2[9] = 'b';
    res2[10] = NDN_TLV_NAME_COMPONENT;
    res2[11] = 1;
    res2[12] = 'c';
    res2[13] = NDN_TLV_NAME_COMPONENT;
    res2[14] = 253;
    res2[15] = 0x01;
    res2[16] = 0xF4;
    for (int i = 17; i < 517; ++i)
	res2[i] = 'd';
    shared = ndn_name_append(&nb, buf2, sizeof(buf2));
    TEST_ASSERT_NOT_NULL(shared);
    TEST_ASSERT_EQUAL_INT(sizeof(res2), shared->block.len);
    TEST_ASSERT(0 == memcmp(res2, shared->block.buf, sizeof(res2)));
    ndn_shared_block_release(shared);
}

static void test_ndn_name_get_size_from_block__invalid(void)
{
    uint8_t buf1[] = {NDN_TLV_SELECTORS, 2, 3, 4};
    ndn_block_t block1 = { buf1, sizeof(buf1) };
    TEST_ASSERT_EQUAL_INT(-1, ndn_name_get_size_from_block(NULL));
    TEST_ASSERT_EQUAL_INT(-1, ndn_name_get_size_from_block(&block1));

    uint8_t buf2[] = {NDN_TLV_NAME, 10};
    ndn_block_t block2 = { buf2, sizeof(buf2) };
    TEST_ASSERT_EQUAL_INT(-1, ndn_name_get_size_from_block(&block2));

    ndn_block_t block3 = { buf2, -1 };
    TEST_ASSERT_EQUAL_INT(-1, ndn_name_get_size_from_block(&block3));

    ndn_block_t block4 = { NULL, 10 };
    TEST_ASSERT_EQUAL_INT(-1, ndn_name_get_size_from_block(&block4));
}

static void test_ndn_name_get_size_from_block__valid(void)
{
    uint8_t buf[] = {
	NDN_TLV_NAME, 18,
	NDN_TLV_NAME_COMPONENT, 1, 'a',
	NDN_TLV_NAME_COMPONENT, 1, 'b',
	NDN_TLV_NAME_COMPONENT, 2, 'c', 'd',
	NDN_TLV_NAME_COMPONENT, 3, 'e', 'f', 'g',
	NDN_TLV_NAME_COMPONENT, 1, 'h',
    };
    ndn_block_t block = { buf, sizeof(buf) };
    TEST_ASSERT_EQUAL_INT(5, ndn_name_get_size_from_block(&block));

    uint8_t em[] = { NDN_TLV_NAME, 0, };
    ndn_block_t empty = { em, sizeof(em) };
    TEST_ASSERT_EQUAL_INT(0, ndn_name_get_size_from_block(&empty));
}

static void test_ndn_name_get_component_from_block__all(void)
{
    ndn_name_component_t comp;

    uint8_t em[] = { NDN_TLV_NAME, 0, };
    ndn_block_t empty = { em, sizeof(em) };
    TEST_ASSERT_EQUAL_INT(-1, ndn_name_get_component_from_block(&empty, 0, &comp));

    uint8_t buf[] = {
	NDN_TLV_NAME, 18,
	NDN_TLV_NAME_COMPONENT, 1, 'a',
	NDN_TLV_NAME_COMPONENT, 1, 'b',
	NDN_TLV_NAME_COMPONENT, 2, 'c', 'd',
	NDN_TLV_NAME_COMPONENT, 3, 'e', 'f', 'g',
	NDN_TLV_NAME_COMPONENT, 1, 'h',
    };
    ndn_block_t block = { buf, sizeof(buf) };

    TEST_ASSERT_EQUAL_INT(-1, ndn_name_get_component_from_block(&block, -1, &comp));
    TEST_ASSERT_EQUAL_INT(-1, ndn_name_get_component_from_block(NULL, 0, &comp));
    TEST_ASSERT_EQUAL_INT(-1, ndn_name_get_component_from_block(&block, 0, NULL));
    TEST_ASSERT_EQUAL_INT(-1, ndn_name_get_component_from_block(&block, 100, &comp));

    TEST_ASSERT_EQUAL_INT(0, ndn_name_get_component_from_block(&block, 0, &comp));
    TEST_ASSERT_EQUAL_INT(1, comp.len);
    TEST_ASSERT_EQUAL_INT('a', comp.buf[0]);

    TEST_ASSERT_EQUAL_INT(0, ndn_name_get_component_from_block(&block, 1, &comp));
    TEST_ASSERT_EQUAL_INT(1, comp.len);
    TEST_ASSERT_EQUAL_INT('b', comp.buf[0]);

    TEST_ASSERT_EQUAL_INT(0, ndn_name_get_component_from_block(&block, 2, &comp));
    TEST_ASSERT_EQUAL_INT(2, comp.len);
    TEST_ASSERT_EQUAL_INT('c', comp.buf[0]);
    TEST_ASSERT_EQUAL_INT('d', comp.buf[1]);

    TEST_ASSERT_EQUAL_INT(0, ndn_name_get_component_from_block(&block, 3, &comp));
    TEST_ASSERT_EQUAL_INT(3, comp.len);
    TEST_ASSERT_EQUAL_INT('e', comp.buf[0]);
    TEST_ASSERT_EQUAL_INT('f', comp.buf[1]);
    TEST_ASSERT_EQUAL_INT('g', comp.buf[2]);

    TEST_ASSERT_EQUAL_INT(0, ndn_name_get_component_from_block(&block, 4, &comp));
    TEST_ASSERT_EQUAL_INT(1, comp.len);
    TEST_ASSERT_EQUAL_INT('h', comp.buf[0]);
}

static void test_ndn_name_compare_block__valid(void)
{
    uint8_t buf1[] = {
	NDN_TLV_NAME, 9,
	NDN_TLV_NAME_COMPONENT, 1, 'a',
	NDN_TLV_NAME_COMPONENT, 1, 'b',
	NDN_TLV_NAME_COMPONENT, 1, 'c',
    };
    ndn_block_t name0 = { buf1, sizeof(buf1) }; // URI = /a/b/c
    ndn_block_t name1 = { buf1, sizeof(buf1) }; // URI = /a/b/c

    uint8_t buf2[] = {
	NDN_TLV_NAME, 9,
	NDN_TLV_NAME_COMPONENT, 1, 'a',
	NDN_TLV_NAME_COMPONENT, 1, 'b',
	NDN_TLV_NAME_COMPONENT, 1, 'd',
    };
    ndn_block_t name2 = { buf2, sizeof(buf2) }; // URI = /a/b/d

    uint8_t buf3[] = {
	NDN_TLV_NAME, 10,
	NDN_TLV_NAME_COMPONENT, 1, 'a',
	NDN_TLV_NAME_COMPONENT, 1, 'b',
	NDN_TLV_NAME_COMPONENT, 2, 'c', 'c',
    };
    ndn_block_t name3 = { buf3, sizeof(buf3) }; // URI = /a/b/cc

    uint8_t buf4[] = {
	NDN_TLV_NAME, 12,
	NDN_TLV_NAME_COMPONENT, 1, 'a',
	NDN_TLV_NAME_COMPONENT, 1, 'b',
	NDN_TLV_NAME_COMPONENT, 1, 'c',
	NDN_TLV_NAME_COMPONENT, 1, 'd',
    };
    ndn_block_t name4 = { buf4, sizeof(buf4) }; // URI = /a/b/c/d

    uint8_t em[] = { NDN_TLV_NAME, 0, };
    ndn_block_t empty = { em, sizeof(em) };
    TEST_ASSERT_EQUAL_INT(-2, ndn_name_compare_block(&empty, &name1));
    TEST_ASSERT_EQUAL_INT(0, ndn_name_compare_block(&empty, &empty));
    TEST_ASSERT_EQUAL_INT(2, ndn_name_compare_block(&name1, &empty));

    TEST_ASSERT_EQUAL_INT(0, ndn_name_compare_block(&name0, &name1));
    TEST_ASSERT_EQUAL_INT(-1, ndn_name_compare_block(&name1, &name2));
    TEST_ASSERT_EQUAL_INT(-2, ndn_name_compare_block(&name1, &name4));
    TEST_ASSERT_EQUAL_INT(-1, ndn_name_compare_block(&name2, &name3));
    TEST_ASSERT_EQUAL_INT(1, ndn_name_compare_block(&name3, &name4));
    TEST_ASSERT_EQUAL_INT(1, ndn_name_compare_block(&name2, &name4));
    TEST_ASSERT_EQUAL_INT(2, ndn_name_compare_block(&name4, &name1));
}

Test *tests_ndn_encoding_name_tests(void)
{
    EMB_UNIT_TESTFIXTURES(fixtures) {
	new_TestFixture(test_ndn_name_component_compare__invalid),
	new_TestFixture(test_ndn_name_component_compare__valid),
        new_TestFixture(test_ndn_name_component_wire_encode__invalid),
	new_TestFixture(test_ndn_name_component_wire_encode__valid),
        new_TestFixture(test_ndn_name_compare__invalid),
	new_TestFixture(test_ndn_name_compare__valid),
        new_TestFixture(test_ndn_name_get_component__invalid),
	new_TestFixture(test_ndn_name_get_component__valid),
        new_TestFixture(test_ndn_name_total_length__invalid),
	new_TestFixture(test_ndn_name_total_length__valid),
        new_TestFixture(test_ndn_name_wire_encode__invalid),
	new_TestFixture(test_ndn_name_wire_encode__valid),
        new_TestFixture(test_ndn_name_from_uri__invalid),
	new_TestFixture(test_ndn_name_from_uri__valid),
	new_TestFixture(test_ndn_name_append__all),
	new_TestFixture(test_ndn_name_get_size_from_block__invalid),
	new_TestFixture(test_ndn_name_get_size_from_block__valid),
        new_TestFixture(test_ndn_name_get_component_from_block__all),
	new_TestFixture(test_ndn_name_compare_block__valid),
    };

    EMB_UNIT_TESTCALLER(ndn_encoding_name_tests, NULL, NULL, fixtures);

    return (Test *)&ndn_encoding_name_tests;
}


/* tests for interest.h */

static void test_ndn_interest_create__all(void)
{
    TEST_ASSERT_NULL(ndn_interest_create(NULL, NULL, 4000));

    const char* str = "/a/b/cd/ef";
    ndn_shared_block_t* sn = ndn_name_from_uri(str, strlen(str));
    TEST_ASSERT_NOT_NULL(sn);

    uint32_t lifetime = 0x4000;

    uint8_t result[] = {
	NDN_TLV_INTEREST, 26,
	NDN_TLV_NAME, 14,
	NDN_TLV_NAME_COMPONENT, 1, 'a',
	NDN_TLV_NAME_COMPONENT, 1, 'b',
	NDN_TLV_NAME_COMPONENT, 2, 'c', 'd',
	NDN_TLV_NAME_COMPONENT, 2, 'e', 'f',
    	NDN_TLV_NONCE, 4,
    	0, 0, 0, 0, /* random values that we don't care */
    	NDN_TLV_INTERESTLIFETIME, 2, 0x40, 0,
    };

    ndn_shared_block_t* sb = ndn_interest_create(&sn->block, NULL, lifetime);
    TEST_ASSERT_NOT_NULL(sb);
    TEST_ASSERT_NOT_NULL(sb->block.buf);
    TEST_ASSERT_EQUAL_INT(sizeof(result), sb->block.len);
    TEST_ASSERT(0 == memcmp(sb->block.buf, result, 20));
    TEST_ASSERT(0 == memcmp(sb->block.buf + 24, result + 24, 4));

    ndn_shared_block_release(sn);
    ndn_shared_block_release(sb);
}

static void test_ndn_interest_create2__invalid(void)
{
    uint8_t buf[4] = "abcd";
    ndn_name_component_t comps[4] = {
	{ buf, 4 },
	{ buf, -1 },
	{ NULL, 1 },
	{ buf, 0 },
    };
    ndn_name_t bad1 = { 1, comps + 1 };
    ndn_name_t bad2 = { 1, comps + 2 };
    ndn_name_t bad3 = { 1, comps + 3 };

    TEST_ASSERT_NULL(ndn_interest_create2(NULL, NULL, 4000));
    TEST_ASSERT_NULL(ndn_interest_create2(&bad1, NULL, 4000));
    TEST_ASSERT_NULL(ndn_interest_create2(&bad2, NULL, 4000));
    TEST_ASSERT_NULL(ndn_interest_create2(&bad3, NULL, 4000));
}

static void test_ndn_interest_create2__valid(void)
{
    uint8_t buf[6] = "abcdef";
    ndn_name_component_t comps[4] = {
	{ buf, 1 },
	{ buf + 1, 1 },
	{ buf + 2, 2 },
	{ buf + 4, 2 }
    };
    ndn_name_t name = { 4, comps };  // URI = /a/b/cd/ef
    uint32_t lifetime = 0x4000;

    uint8_t result[] = {
	NDN_TLV_INTEREST, 26,
	NDN_TLV_NAME, 14,
	NDN_TLV_NAME_COMPONENT, 1, 'a',
	NDN_TLV_NAME_COMPONENT, 1, 'b',
	NDN_TLV_NAME_COMPONENT, 2, 'c', 'd',
	NDN_TLV_NAME_COMPONENT, 2, 'e', 'f',
    	NDN_TLV_NONCE, 4,
    	0, 0, 0, 0, /* random values that we don't care */
    	NDN_TLV_INTERESTLIFETIME, 2, 0x40, 0,
    };

    ndn_shared_block_t* sb = ndn_interest_create2(&name, NULL, lifetime);
    TEST_ASSERT_NOT_NULL(sb);
    TEST_ASSERT_NOT_NULL(sb->block.buf);
    TEST_ASSERT_EQUAL_INT(sizeof(result), sb->block.len);
    TEST_ASSERT(0 == memcmp(sb->block.buf, result, 20));
    TEST_ASSERT(0 == memcmp(sb->block.buf + 24, result + 24, 4));

    ndn_shared_block_release(sb);
}

static void test_ndn_interest_get_name__invalid(void)
{
    ndn_block_t name;

    uint8_t buf1[] = {NDN_TLV_INTEREST, 100, NDN_TLV_SELECTORS, 2, 3, 4};
    ndn_block_t block1 = {buf1, sizeof(buf1)};
    TEST_ASSERT_EQUAL_INT(-1, ndn_interest_get_name(NULL, &name));
    TEST_ASSERT_EQUAL_INT(-1, ndn_interest_get_name(&block1, NULL));
    TEST_ASSERT_EQUAL_INT(-1, ndn_interest_get_name(&block1, &name));

    uint8_t buf2[] = {NDN_TLV_INTEREST, 100, NDN_TLV_NAME, 10};
    ndn_block_t block2 = {buf2, sizeof(buf2)};
    TEST_ASSERT_EQUAL_INT(-1, ndn_interest_get_name(&block2, &name));

    uint8_t buf3[]  = {NDN_TLV_SELECTORS, 100, NDN_TLV_NAME, 10};
    ndn_block_t block3 = {buf3, sizeof(buf3)};
    TEST_ASSERT_EQUAL_INT(-1, ndn_interest_get_name(&block3, &name));
}

static void test_ndn_interest_get_name__valid(void)
{
    ndn_block_t name;

    uint8_t buf[] = {
	NDN_TLV_INTEREST, 26,
	NDN_TLV_NAME, 14,
	NDN_TLV_NAME_COMPONENT, 1, 'a',
	NDN_TLV_NAME_COMPONENT, 1, 'b',
	NDN_TLV_NAME_COMPONENT, 2, 'c', 'd',
	NDN_TLV_NAME_COMPONENT, 2, 'e', 'f',
    };
    ndn_block_t block = {buf, sizeof(buf)};
    TEST_ASSERT_EQUAL_INT(0, ndn_interest_get_name(&block, &name));
    TEST_ASSERT(name.buf == buf + 2);
    TEST_ASSERT_EQUAL_INT(16, name.len);
}

static void test_ndn_interest_get_nonce__valid(void)
{
    uint32_t nonce;

    uint8_t buf[] = {
	NDN_TLV_INTEREST, 26,
	NDN_TLV_NAME, 14,
	NDN_TLV_NAME_COMPONENT, 1, 'a',
	NDN_TLV_NAME_COMPONENT, 1, 'b',
	NDN_TLV_NAME_COMPONENT, 2, 'c', 'd',
	NDN_TLV_NAME_COMPONENT, 2, 'e', 'f',
    	NDN_TLV_NONCE, 4,
	0x76, 0x54, 0x32, 0x10,
    	NDN_TLV_INTERESTLIFETIME, 2, 0x40, 0,
    };
    ndn_block_t block = {buf, sizeof(buf)};
    TEST_ASSERT_EQUAL_INT(0, ndn_interest_get_nonce(&block, &nonce));
    TEST_ASSERT_EQUAL_INT(0x76543210, nonce);
}

static void test_ndn_interest_get_lifetime__valid(void)
{
    uint32_t lifetime;

    uint8_t buf[] = {
	NDN_TLV_INTEREST, 26,
	NDN_TLV_NAME, 14,
	NDN_TLV_NAME_COMPONENT, 1, 'a',
	NDN_TLV_NAME_COMPONENT, 1, 'b',
	NDN_TLV_NAME_COMPONENT, 2, 'c', 'd',
	NDN_TLV_NAME_COMPONENT, 2, 'e', 'f',
    	NDN_TLV_NONCE, 4,
	0x76, 0x54, 0x32, 0x10,
    	NDN_TLV_INTERESTLIFETIME, 2, 0x40, 0,
    };
    ndn_block_t block = {buf, sizeof(buf)};
    TEST_ASSERT_EQUAL_INT(0, ndn_interest_get_lifetime(&block, &lifetime));
    TEST_ASSERT_EQUAL_INT(0x4000, lifetime);
}

Test *tests_ndn_encoding_interest_tests(void)
{
    EMB_UNIT_TESTFIXTURES(fixtures) {
        new_TestFixture(test_ndn_interest_create__all),
        new_TestFixture(test_ndn_interest_create2__invalid),
	new_TestFixture(test_ndn_interest_create2__valid),
	new_TestFixture(test_ndn_interest_get_name__invalid),
	new_TestFixture(test_ndn_interest_get_name__valid),
	new_TestFixture(test_ndn_interest_get_nonce__valid),
	new_TestFixture(test_ndn_interest_get_lifetime__valid),
    };

    EMB_UNIT_TESTCALLER(ndn_encoding_interest_tests, set_up, NULL, fixtures);

    return (Test *)&ndn_encoding_interest_tests;
}

/* tests for metainfo.h */

static void test_ndn_metainfo_total_length__all(void)
{
    TEST_ASSERT_EQUAL_INT(-1, ndn_metainfo_total_length(NULL));

    ndn_metainfo_t meta1 = { -1, -1 };
    TEST_ASSERT_EQUAL_INT(2, ndn_metainfo_total_length(&meta1));

    ndn_metainfo_t meta2 = { -1, 1 };
    TEST_ASSERT_EQUAL_INT(5, ndn_metainfo_total_length(&meta2));

    ndn_metainfo_t meta3 = { -1, 0x100 };
    TEST_ASSERT_EQUAL_INT(6, ndn_metainfo_total_length(&meta3));

    ndn_metainfo_t meta4 = { 1, -1 };
    TEST_ASSERT_EQUAL_INT(5, ndn_metainfo_total_length(&meta4));

    ndn_metainfo_t meta5 = { 1, 0x100 };
    TEST_ASSERT_EQUAL_INT(9, ndn_metainfo_total_length(&meta5));
}

static void test_ndn_metainfo_wire_encode__all(void)
{
    uint8_t res[16];
    TEST_ASSERT_EQUAL_INT(-1, ndn_metainfo_wire_encode(NULL, res, sizeof(res)));

    ndn_metainfo_t meta1 = { -1, -1 };
    uint8_t buf1[] = { NDN_TLV_METAINFO, 0 };
    TEST_ASSERT_EQUAL_INT(-1, ndn_metainfo_wire_encode(&meta1, NULL, 0));
    TEST_ASSERT_EQUAL_INT(-1, ndn_metainfo_wire_encode(&meta1, res, -1));
    TEST_ASSERT_EQUAL_INT(2, ndn_metainfo_wire_encode(&meta1, res, sizeof(res)));
    TEST_ASSERT(0 == memcmp(res, buf1, sizeof(buf1)));

    ndn_metainfo_t meta2 = { -1, 1 };
    uint8_t buf2[] = {
	NDN_TLV_METAINFO, 3,
	NDN_TLV_FRESHNESS_PERIOD, 1, 1,
    };
    TEST_ASSERT_EQUAL_INT(5, ndn_metainfo_wire_encode(&meta2, res, sizeof(res)));
    TEST_ASSERT(0 == memcmp(res, buf2, sizeof(buf2)));

    ndn_metainfo_t meta3 = { -1, 0x100 };
    uint8_t buf3[] = {
	NDN_TLV_METAINFO, 4,
	NDN_TLV_FRESHNESS_PERIOD, 2, 0x01, 0,
    };
    TEST_ASSERT_EQUAL_INT(6, ndn_metainfo_wire_encode(&meta3, res, sizeof(res)));
    TEST_ASSERT(0 == memcmp(res, buf3, sizeof(buf3)));

    ndn_metainfo_t meta4 = { 1, -1 };
    uint8_t buf4[] = {
	NDN_TLV_METAINFO, 3,
	NDN_TLV_CONTENT_TYPE, 1, 1,
    };
    TEST_ASSERT_EQUAL_INT(5, ndn_metainfo_wire_encode(&meta4, res, sizeof(res)));
    TEST_ASSERT(0 == memcmp(res, buf4, sizeof(buf4)));

    ndn_metainfo_t meta5 = { 1, 0x100 };
    uint8_t buf5[] = {
	NDN_TLV_METAINFO, 7,
	NDN_TLV_CONTENT_TYPE, 1, 1,
	NDN_TLV_FRESHNESS_PERIOD, 2, 0x01, 0,
    };
    TEST_ASSERT_EQUAL_INT(9, ndn_metainfo_wire_encode(&meta5, res, sizeof(res)));
    TEST_ASSERT(0 == memcmp(res, buf5, sizeof(buf5)));
}

static void test_ndn_metainfo_from_block__invalid(void)
{
    ndn_metainfo_t meta;
    TEST_ASSERT_EQUAL_INT(-1, ndn_metainfo_from_block(NULL, 1, &meta));

    uint8_t buf1[] = {
	NDN_TLV_NAME, 10, 
    };
    TEST_ASSERT_EQUAL_INT(-1, ndn_metainfo_from_block(buf1, sizeof(buf1), NULL));
    TEST_ASSERT_EQUAL_INT(-1, ndn_metainfo_from_block(buf1, -10, &meta));
    TEST_ASSERT_EQUAL_INT(-1, ndn_metainfo_from_block(buf1, sizeof(buf1), &meta));

    uint8_t buf2[] = {
	NDN_TLV_METAINFO, 2,
	NDN_TLV_CONTENT_TYPE, 1, 1,
    };
    TEST_ASSERT_EQUAL_INT(-1, ndn_metainfo_from_block(buf2, sizeof(buf2), &meta));

    uint8_t buf3[] = {
	NDN_TLV_METAINFO, 20,
	NDN_TLV_CONTENT_TYPE, 1, 1,
    };
    TEST_ASSERT_EQUAL_INT(-1, ndn_metainfo_from_block(buf3, sizeof(buf3), &meta));
}

static void test_ndn_metainfo_from_block__valid(void)
{
    ndn_metainfo_t meta;

    uint8_t buf0[] = { NDN_TLV_METAINFO, 0 };
    TEST_ASSERT_EQUAL_INT(2, ndn_metainfo_from_block(buf0, sizeof(buf0), &meta));
    TEST_ASSERT_EQUAL_INT(-1, meta.content_type);
    TEST_ASSERT_EQUAL_INT(-1, meta.freshness);

    uint8_t buf1[] = {
	NDN_TLV_METAINFO, 4,
	NDN_TLV_CONTENT_TYPE, 2, 0x12, 0x34,
    };
    TEST_ASSERT_EQUAL_INT(6, ndn_metainfo_from_block(buf1, sizeof(buf1), &meta));
    TEST_ASSERT_EQUAL_INT(0x1234, meta.content_type);

    uint8_t buf2[] = {
	NDN_TLV_METAINFO, 4,
	NDN_TLV_FRESHNESS_PERIOD, 2, 0x12, 0x34,
    };
    TEST_ASSERT_EQUAL_INT(6, ndn_metainfo_from_block(buf2, sizeof(buf2), &meta));
    TEST_ASSERT_EQUAL_INT(0x1234, meta.freshness);

    uint8_t buf3[] = {
	NDN_TLV_METAINFO, 8,
	NDN_TLV_CONTENT_TYPE, 2, 0x43, 0x21,
	NDN_TLV_FRESHNESS_PERIOD, 2, 0x12, 0x34,
    };
    TEST_ASSERT_EQUAL_INT(10, ndn_metainfo_from_block(buf3, sizeof(buf3), &meta));
    TEST_ASSERT_EQUAL_INT(0x4321, meta.content_type);
    TEST_ASSERT_EQUAL_INT(0x1234, meta.freshness);

    uint8_t buf4[] = {
	NDN_TLV_METAINFO, 12,
	NDN_TLV_CONTENT_TYPE, 2, 0x98, 0x76,
	NDN_TLV_FRESHNESS_PERIOD, 2, 0x54, 0x32,
	NDN_TLV_NAME_COMPONENT, 2, 1, 1,
    };
    TEST_ASSERT_EQUAL_INT(14, ndn_metainfo_from_block(buf4, sizeof(buf4), &meta));
    TEST_ASSERT_EQUAL_INT(0x9876, meta.content_type);
    TEST_ASSERT_EQUAL_INT(0x5432, meta.freshness);
}

Test *tests_ndn_encoding_metainfo_tests(void)
{
    EMB_UNIT_TESTFIXTURES(fixtures) {
        new_TestFixture(test_ndn_metainfo_total_length__all),
	new_TestFixture(test_ndn_metainfo_wire_encode__all),
	new_TestFixture(test_ndn_metainfo_from_block__invalid),
	new_TestFixture(test_ndn_metainfo_from_block__valid),
    };

    EMB_UNIT_TESTCALLER(ndn_encoding_metainfo_tests, NULL, NULL, fixtures);

    return (Test *)&ndn_encoding_metainfo_tests;
}

/* tests for data.h */

static void test_ndn_data_create__no_keylocator(void)
{
    const char* str = "/a/b/c/d";
    ndn_shared_block_t* sn = ndn_name_from_uri(str, strlen(str));
    TEST_ASSERT_NOT_NULL(sn);

    ndn_metainfo_t meta = { NDN_CONTENT_TYPE_BLOB, 0x7102034 };

    uint8_t con[] = { 0x91, 0x82, 0x73, 0x64, 0x55, 0x44, 0x33, 0x22, 0x10 };
    ndn_block_t content;
    content.buf = con;
    content.len = sizeof(con);

    uint8_t result[] = {
	NDN_TLV_DATA, 75,
	NDN_TLV_NAME, 12,
	NDN_TLV_NAME_COMPONENT, 1, 'a',
	NDN_TLV_NAME_COMPONENT, 1, 'b',
	NDN_TLV_NAME_COMPONENT, 1, 'c',
	NDN_TLV_NAME_COMPONENT, 1, 'd',
	NDN_TLV_METAINFO, 9,
	NDN_TLV_CONTENT_TYPE, 1, NDN_CONTENT_TYPE_BLOB,
	NDN_TLV_FRESHNESS_PERIOD, 4, 7, 0x10, 0x20, 0x34,
	NDN_TLV_CONTENT, 9,
	0x91, 0x82, 0x73, 0x64, 0x55, 0x44, 0x33, 0x22, 0x10,
	NDN_TLV_SIGNATURE_INFO, 3,
	NDN_TLV_SIGNATURE_TYPE, 1, NDN_SIG_TYPE_DIGEST_SHA256,
	NDN_TLV_SIGNATURE_VALUE, 32,
    };

    uint8_t h[32];
    sha256(result + 2, sizeof(result) - 4, h);

    ndn_shared_block_t* data =
	ndn_data_create(&sn->block, &meta, &content,
			NDN_SIG_TYPE_DIGEST_SHA256, NULL, NULL, 0);
    TEST_ASSERT_NOT_NULL(data);
    TEST_ASSERT(0 == memcmp(data->block.buf, result, sizeof(result)));
    TEST_ASSERT(0 == memcmp(data->block.buf + sizeof(result), h, sizeof(h)));

    ndn_shared_block_release(data);

    unsigned char key[] = { 0xa1, 0xb9, 0xc8, 0xd7, 0xe0, 0xf3, 0xf2, 0xe4 };

    result[42] = NDN_SIG_TYPE_HMAC_SHA256;
    hmac_sha256(key, sizeof(key), (const unsigned*)(result + 2),
		sizeof(result) - 4, h);
    data = ndn_data_create(&sn->block, &meta, &content,
			   NDN_SIG_TYPE_HMAC_SHA256, NULL, key, sizeof(key));
    TEST_ASSERT_NOT_NULL(data);
    TEST_ASSERT(0 == memcmp(data->block.buf, result, sizeof(result)));
    TEST_ASSERT(0 == memcmp(data->block.buf + sizeof(result), h, sizeof(h)));

    ndn_shared_block_release(data);

    uint8_t ecc_key_pri[] = { 0x38, 0x67, 0x54, 0x73, 0x8B, 0x72, 0x4C, 0xD6,
			      0x3E, 0xBD, 0x52, 0xF3, 0x64, 0xD8, 0xF5, 0x7F,
			      0xB5, 0xE6, 0xF2, 0x9F, 0xC2, 0x7B, 0xD6, 0x90,
			      0x42, 0x9D, 0xC8, 0xCE, 0xF0, 0xDE, 0x75, 0xB3 };
    uint8_t ecc_key_pub[] = { 0x2C, 0x3C, 0x18, 0xCB, 0x31, 0x88, 0x0B, 0xC3,
			      0x73, 0xF4, 0x4A, 0xD4, 0x3F, 0x8C, 0x80, 0x24,
			      0xD4, 0x8E, 0xBE, 0xB4, 0xAD, 0xF0, 0x69, 0xA6,
			      0xFE, 0x29, 0x12, 0xAC, 0xC1, 0xE1, 0x26, 0x7E,
			      0x2B, 0x25, 0x69, 0x02, 0xD5, 0x85, 0x51, 0x4B,
			      0x91, 0xAC, 0xB9, 0xD1, 0x19, 0xE9, 0x5E, 0x97,
			      0x20, 0xBB, 0x16, 0x2A, 0xD3, 0x2F, 0xB5, 0x11,
			      0x1B, 0xD1, 0xAF, 0x76, 0xDB, 0xAD, 0xB8, 0xCE };

    result[1] += 32;
    result[42] = NDN_SIG_TYPE_ECDSA_SHA256;
    result[44] = 64;
    data = ndn_data_create(&sn->block, &meta, &content,
			   NDN_SIG_TYPE_ECDSA_SHA256, NULL, ecc_key_pri, 32);
    TEST_ASSERT(0 == memcmp(data->block.buf, result, sizeof(result)));
    uECC_Curve curve = uECC_secp256r1();
    sha256(result + 2, sizeof(result) - 4, h);
    TEST_ASSERT(uECC_verify(ecc_key_pub, h, sizeof(h),
			    data->block.buf + sizeof(result), curve) != 0);

    ndn_shared_block_release(data);

    ndn_shared_block_release(sn);
}

static void test_ndn_data_create__with_keylocator(void)
{
    const char* str = "/a/b/c/d";
    ndn_shared_block_t* sn = ndn_name_from_uri(str, strlen(str));
    TEST_ASSERT_NOT_NULL(sn);

    const char* strk = "/a/b";
    ndn_shared_block_t* skn = ndn_name_from_uri(strk, strlen(strk));
    TEST_ASSERT_NOT_NULL(skn);

    ndn_metainfo_t meta = { NDN_CONTENT_TYPE_BLOB, 0x7102034 };

    uint8_t con[] = { 0x91, 0x82, 0x73, 0x64, 0x55, 0x44, 0x33, 0x22, 0x10 };
    ndn_block_t content;
    content.buf = con;
    content.len = sizeof(con);

    uint8_t result[] = {
	NDN_TLV_DATA, 117,
	NDN_TLV_NAME, 12,
	NDN_TLV_NAME_COMPONENT, 1, 'a',
	NDN_TLV_NAME_COMPONENT, 1, 'b',
	NDN_TLV_NAME_COMPONENT, 1, 'c',
	NDN_TLV_NAME_COMPONENT, 1, 'd',
	NDN_TLV_METAINFO, 9,
	NDN_TLV_CONTENT_TYPE, 1, NDN_CONTENT_TYPE_BLOB,
	NDN_TLV_FRESHNESS_PERIOD, 4, 7, 0x10, 0x20, 0x34,
	NDN_TLV_CONTENT, 9,
	0x91, 0x82, 0x73, 0x64, 0x55, 0x44, 0x33, 0x22, 0x10,
	NDN_TLV_SIGNATURE_INFO, 13,
	NDN_TLV_SIGNATURE_TYPE, 1, NDN_SIG_TYPE_ECDSA_SHA256,
	NDN_TLV_KEY_LOCATOR, 8, NDN_TLV_NAME, 6,
	NDN_TLV_NAME_COMPONENT, 1, 'a',
	NDN_TLV_NAME_COMPONENT, 1, 'b',
	NDN_TLV_SIGNATURE_VALUE, 64,
    };

    uint8_t ecc_key_pri[] = { 0x38, 0x67, 0x54, 0x73, 0x8B, 0x72, 0x4C, 0xD6,
			      0x3E, 0xBD, 0x52, 0xF3, 0x64, 0xD8, 0xF5, 0x7F,
			      0xB5, 0xE6, 0xF2, 0x9F, 0xC2, 0x7B, 0xD6, 0x90,
			      0x42, 0x9D, 0xC8, 0xCE, 0xF0, 0xDE, 0x75, 0xB3 };
    uint8_t ecc_key_pub[] = { 0x2C, 0x3C, 0x18, 0xCB, 0x31, 0x88, 0x0B, 0xC3,
			      0x73, 0xF4, 0x4A, 0xD4, 0x3F, 0x8C, 0x80, 0x24,
			      0xD4, 0x8E, 0xBE, 0xB4, 0xAD, 0xF0, 0x69, 0xA6,
			      0xFE, 0x29, 0x12, 0xAC, 0xC1, 0xE1, 0x26, 0x7E,
			      0x2B, 0x25, 0x69, 0x02, 0xD5, 0x85, 0x51, 0x4B,
			      0x91, 0xAC, 0xB9, 0xD1, 0x19, 0xE9, 0x5E, 0x97,
			      0x20, 0xBB, 0x16, 0x2A, 0xD3, 0x2F, 0xB5, 0x11,
			      0x1B, 0xD1, 0xAF, 0x76, 0xDB, 0xAD, 0xB8, 0xCE };


    ndn_shared_block_t* data =
	ndn_data_create(&sn->block, &meta, &content,
			NDN_SIG_TYPE_ECDSA_SHA256, &skn->block,
			ecc_key_pri, 32);
    TEST_ASSERT_NOT_NULL(data);
    TEST_ASSERT(0 == memcmp(data->block.buf, result, sizeof(result)));

    uECC_Curve curve = uECC_secp256r1();
    uint8_t h[32];
    sha256(result + 2, sizeof(result) - 4, h);
    TEST_ASSERT(uECC_verify(ecc_key_pub, h, sizeof(h),
			    data->block.buf + sizeof(result), curve) != 0);

    ndn_shared_block_release(data);

    ndn_shared_block_release(sn);
    ndn_shared_block_release(skn);
}

static void test_ndn_data_create2__no_keylocator(void)
{
    uint8_t buf[6] = "abcd";
    ndn_name_component_t comps[4] = {
	{ buf, 1 },
	{ buf + 1, 1 },
	{ buf + 2, 1 },
	{ buf + 3, 1 }
    };
    ndn_name_t name = { 4, comps };  // URI = /a/b/c/d

    ndn_metainfo_t meta = { NDN_CONTENT_TYPE_BLOB, 0x7102034 };

    uint8_t con[] = { 0x91, 0x82, 0x73, 0x64, 0x55, 0x44, 0x33, 0x22, 0x10 };
    ndn_block_t content;
    content.buf = con;
    content.len = sizeof(con);

    uint8_t result[] = {
	NDN_TLV_DATA, 75,
	NDN_TLV_NAME, 12,
	NDN_TLV_NAME_COMPONENT, 1, 'a',
	NDN_TLV_NAME_COMPONENT, 1, 'b',
	NDN_TLV_NAME_COMPONENT, 1, 'c',
	NDN_TLV_NAME_COMPONENT, 1, 'd',
	NDN_TLV_METAINFO, 9,
	NDN_TLV_CONTENT_TYPE, 1, NDN_CONTENT_TYPE_BLOB,
	NDN_TLV_FRESHNESS_PERIOD, 4, 7, 0x10, 0x20, 0x34,
	NDN_TLV_CONTENT, 9,
	0x91, 0x82, 0x73, 0x64, 0x55, 0x44, 0x33, 0x22, 0x10,
	NDN_TLV_SIGNATURE_INFO, 3,
	NDN_TLV_SIGNATURE_TYPE, 1, NDN_SIG_TYPE_DIGEST_SHA256,
	NDN_TLV_SIGNATURE_VALUE, 32,
    };

    uint8_t h[32];
    sha256(result + 2, sizeof(result) - 4, h);
    
    ndn_shared_block_t* data =
	ndn_data_create2(&name, &meta, &content,
			 NDN_SIG_TYPE_DIGEST_SHA256, NULL, NULL, 0);
    TEST_ASSERT_NOT_NULL(data);
    TEST_ASSERT(0 == memcmp(data->block.buf, result, sizeof(result)));
    TEST_ASSERT(0 == memcmp(data->block.buf + sizeof(result), h, sizeof(h)));

    ndn_shared_block_release(data);

    unsigned char key[] = { 0xa1, 0xb9, 0xc8, 0xd7, 0xe0, 0xf3, 0xf2, 0xe4 };

    result[42] = NDN_SIG_TYPE_HMAC_SHA256;
    hmac_sha256(key, sizeof(key), (const unsigned*)(result + 2),
		sizeof(result) - 4, h);
    data = ndn_data_create2(&name, &meta, &content,
			    NDN_SIG_TYPE_HMAC_SHA256, NULL, key, sizeof(key));
    TEST_ASSERT_NOT_NULL(data);
    TEST_ASSERT(0 == memcmp(data->block.buf, result, sizeof(result)));
    TEST_ASSERT(0 == memcmp(data->block.buf + sizeof(result), h, sizeof(h)));

    ndn_shared_block_release(data);

    uint8_t ecc_key_pri[] = { 0x38, 0x67, 0x54, 0x73, 0x8B, 0x72, 0x4C, 0xD6,
			      0x3E, 0xBD, 0x52, 0xF3, 0x64, 0xD8, 0xF5, 0x7F,
			      0xB5, 0xE6, 0xF2, 0x9F, 0xC2, 0x7B, 0xD6, 0x90,
			      0x42, 0x9D, 0xC8, 0xCE, 0xF0, 0xDE, 0x75, 0xB3 };
    uint8_t ecc_key_pub[] = { 0x2C, 0x3C, 0x18, 0xCB, 0x31, 0x88, 0x0B, 0xC3,
			      0x73, 0xF4, 0x4A, 0xD4, 0x3F, 0x8C, 0x80, 0x24,
			      0xD4, 0x8E, 0xBE, 0xB4, 0xAD, 0xF0, 0x69, 0xA6,
			      0xFE, 0x29, 0x12, 0xAC, 0xC1, 0xE1, 0x26, 0x7E,
			      0x2B, 0x25, 0x69, 0x02, 0xD5, 0x85, 0x51, 0x4B,
			      0x91, 0xAC, 0xB9, 0xD1, 0x19, 0xE9, 0x5E, 0x97,
			      0x20, 0xBB, 0x16, 0x2A, 0xD3, 0x2F, 0xB5, 0x11,
			      0x1B, 0xD1, 0xAF, 0x76, 0xDB, 0xAD, 0xB8, 0xCE };

    result[1] += 32;
    result[42] = NDN_SIG_TYPE_ECDSA_SHA256;
    result[44] = 64;
    data = ndn_data_create2(&name, &meta, &content,
			    NDN_SIG_TYPE_ECDSA_SHA256, NULL, ecc_key_pri, 32);
    TEST_ASSERT(0 == memcmp(data->block.buf, result, sizeof(result)));
    uECC_Curve curve = uECC_secp256r1();
    sha256(result + 2, sizeof(result) - 4, h);
    TEST_ASSERT(uECC_verify(ecc_key_pub, h, sizeof(h),
			    data->block.buf + sizeof(result), curve) != 0);

    ndn_shared_block_release(data);
}

static void test_ndn_data_create2__with_keylocator(void)
{
    uint8_t buf[6] = "abcd";
    ndn_name_component_t comps[4] = {
	{ buf, 1 },
	{ buf + 1, 1 },
	{ buf + 2, 1 },
	{ buf + 3, 1 }
    };
    ndn_name_t name = { 4, comps };  // URI = /a/b/c/d
    ndn_name_t key_name = {2, comps };  // URI = /a/b

    ndn_metainfo_t meta = { NDN_CONTENT_TYPE_BLOB, 0x7102034 };

    uint8_t con[] = { 0x91, 0x82, 0x73, 0x64, 0x55, 0x44, 0x33, 0x22, 0x10 };
    ndn_block_t content;
    content.buf = con;
    content.len = sizeof(con);

    uint8_t result[] = {
	NDN_TLV_DATA, 117,
	NDN_TLV_NAME, 12,
	NDN_TLV_NAME_COMPONENT, 1, 'a',
	NDN_TLV_NAME_COMPONENT, 1, 'b',
	NDN_TLV_NAME_COMPONENT, 1, 'c',
	NDN_TLV_NAME_COMPONENT, 1, 'd',
	NDN_TLV_METAINFO, 9,
	NDN_TLV_CONTENT_TYPE, 1, NDN_CONTENT_TYPE_BLOB,
	NDN_TLV_FRESHNESS_PERIOD, 4, 7, 0x10, 0x20, 0x34,
	NDN_TLV_CONTENT, 9,
	0x91, 0x82, 0x73, 0x64, 0x55, 0x44, 0x33, 0x22, 0x10,
	NDN_TLV_SIGNATURE_INFO, 13,
	NDN_TLV_SIGNATURE_TYPE, 1, NDN_SIG_TYPE_ECDSA_SHA256,
	NDN_TLV_KEY_LOCATOR, 8, NDN_TLV_NAME, 6,
	NDN_TLV_NAME_COMPONENT, 1, 'a',
	NDN_TLV_NAME_COMPONENT, 1, 'b',
	NDN_TLV_SIGNATURE_VALUE, 64,
    };

    uint8_t ecc_key_pri[] = { 0x38, 0x67, 0x54, 0x73, 0x8B, 0x72, 0x4C, 0xD6,
			      0x3E, 0xBD, 0x52, 0xF3, 0x64, 0xD8, 0xF5, 0x7F,
			      0xB5, 0xE6, 0xF2, 0x9F, 0xC2, 0x7B, 0xD6, 0x90,
			      0x42, 0x9D, 0xC8, 0xCE, 0xF0, 0xDE, 0x75, 0xB3 };
    uint8_t ecc_key_pub[] = { 0x2C, 0x3C, 0x18, 0xCB, 0x31, 0x88, 0x0B, 0xC3,
			      0x73, 0xF4, 0x4A, 0xD4, 0x3F, 0x8C, 0x80, 0x24,
			      0xD4, 0x8E, 0xBE, 0xB4, 0xAD, 0xF0, 0x69, 0xA6,
			      0xFE, 0x29, 0x12, 0xAC, 0xC1, 0xE1, 0x26, 0x7E,
			      0x2B, 0x25, 0x69, 0x02, 0xD5, 0x85, 0x51, 0x4B,
			      0x91, 0xAC, 0xB9, 0xD1, 0x19, 0xE9, 0x5E, 0x97,
			      0x20, 0xBB, 0x16, 0x2A, 0xD3, 0x2F, 0xB5, 0x11,
			      0x1B, 0xD1, 0xAF, 0x76, 0xDB, 0xAD, 0xB8, 0xCE };


    ndn_shared_block_t* data =
	ndn_data_create2(&name, &meta, &content, NDN_SIG_TYPE_ECDSA_SHA256,
			 &key_name, ecc_key_pri, 32);
    TEST_ASSERT_NOT_NULL(data);
    TEST_ASSERT(0 == memcmp(data->block.buf, result, sizeof(result)));

    uECC_Curve curve = uECC_secp256r1();
    uint8_t h[32];
    sha256(result + 2, sizeof(result) - 4, h);
    TEST_ASSERT(uECC_verify(ecc_key_pub, h, sizeof(h),
			    data->block.buf + sizeof(result), curve) != 0);

    ndn_shared_block_release(data);
}

static void test_ndn_data_get_name__valid(void)
{
    uint8_t buf[] = {
	NDN_TLV_DATA, 75,
	NDN_TLV_NAME, 12,
	NDN_TLV_NAME_COMPONENT, 1, 'a',
	NDN_TLV_NAME_COMPONENT, 1, 'b',
	NDN_TLV_NAME_COMPONENT, 1, 'c',
	NDN_TLV_NAME_COMPONENT, 1, 'd',
	NDN_TLV_METAINFO, 9,
	NDN_TLV_CONTENT_TYPE, 1, NDN_CONTENT_TYPE_BLOB,
	NDN_TLV_FRESHNESS_PERIOD, 4, 7, 0x10, 0x20, 0x34,
	NDN_TLV_CONTENT, 9,
	0x91, 0x82, 0x73, 0x64, 0x55, 0x44, 0x33, 0x22, 0x10,
	NDN_TLV_SIGNATURE_INFO, 3,
	NDN_TLV_SIGNATURE_TYPE, 1, NDN_SIG_TYPE_DIGEST_SHA256,
	NDN_TLV_SIGNATURE_VALUE, 32,
	0xe3, 0x8f, 0x85, 0x5b, 0x51, 0x7f, 0x42, 0xa6, 0x4f, 0x5a, 0x34,
	0x38, 0x00, 0x0b, 0x2b, 0x34, 0xa5, 0x85, 0x1c, 0xc9, 0x97, 0xf2,
	0x0c, 0x8c, 0x55, 0x28, 0xf5, 0xaf, 0xc0, 0xc2, 0x58, 0x54,
    };

    ndn_block_t data = { buf, sizeof(buf) };

    ndn_block_t name;
    TEST_ASSERT_EQUAL_INT(0, ndn_data_get_name(&data, &name));
    TEST_ASSERT(0 == memcmp(buf + 2, name.buf, name.len));
}

static void test_ndn_data_get_metainfo__valid(void)
{
    uint8_t buf[] = {
	NDN_TLV_DATA, 75,
	NDN_TLV_NAME, 12,
	NDN_TLV_NAME_COMPONENT, 1, 'a',
	NDN_TLV_NAME_COMPONENT, 1, 'b',
	NDN_TLV_NAME_COMPONENT, 1, 'c',
	NDN_TLV_NAME_COMPONENT, 1, 'd',
	NDN_TLV_METAINFO, 9,
	NDN_TLV_CONTENT_TYPE, 1, NDN_CONTENT_TYPE_BLOB,
	NDN_TLV_FRESHNESS_PERIOD, 4, 7, 0x10, 0x20, 0x34,
	NDN_TLV_CONTENT, 9,
	0x91, 0x82, 0x73, 0x64, 0x55, 0x44, 0x33, 0x22, 0x10,
	NDN_TLV_SIGNATURE_INFO, 3,
	NDN_TLV_SIGNATURE_TYPE, 1, NDN_SIG_TYPE_DIGEST_SHA256,
	NDN_TLV_SIGNATURE_VALUE, 32,
	0xe3, 0x8f, 0x85, 0x5b, 0x51, 0x7f, 0x42, 0xa6, 0x4f, 0x5a, 0x34,
	0x38, 0x00, 0x0b, 0x2b, 0x34, 0xa5, 0x85, 0x1c, 0xc9, 0x97, 0xf2,
	0x0c, 0x8c, 0x55, 0x28, 0xf5, 0xaf, 0xc0, 0xc2, 0x58, 0x54,
    };

    ndn_block_t data = { buf, sizeof(buf) };

    ndn_metainfo_t meta;
    TEST_ASSERT_EQUAL_INT(0, ndn_data_get_metainfo(&data, &meta));
    TEST_ASSERT_EQUAL_INT(NDN_CONTENT_TYPE_BLOB, meta.content_type);
    TEST_ASSERT_EQUAL_INT(0x7102034, meta.freshness);

    uint8_t buf1[] = {
	NDN_TLV_DATA, 69,
	NDN_TLV_NAME, 12,
	NDN_TLV_NAME_COMPONENT, 1, 'a',
	NDN_TLV_NAME_COMPONENT, 1, 'b',
	NDN_TLV_NAME_COMPONENT, 1, 'c',
	NDN_TLV_NAME_COMPONENT, 1, 'd',
	NDN_TLV_METAINFO, 3,
	NDN_TLV_CONTENT_TYPE, 1, NDN_CONTENT_TYPE_BLOB,
	NDN_TLV_CONTENT, 9,
	0x91, 0x82, 0x73, 0x64, 0x55, 0x44, 0x33, 0x22, 0x10,
	NDN_TLV_SIGNATURE_INFO, 3,
	NDN_TLV_SIGNATURE_TYPE, 1, NDN_SIG_TYPE_DIGEST_SHA256,
	NDN_TLV_SIGNATURE_VALUE, 32,
	0xe3, 0x8f, 0x85, 0x5b, 0x51, 0x7f, 0x42, 0xa6, 0x4f, 0x5a, 0x34,
	0x38, 0x00, 0x0b, 0x2b, 0x34, 0xa5, 0x85, 0x1c, 0xc9, 0x97, 0xf2,
	0x0c, 0x8c, 0x55, 0x28, 0xf5, 0xaf, 0xc0, 0xc2, 0x58, 0x54,
    };

    ndn_block_t data1 = { buf1, sizeof(buf1) };
    TEST_ASSERT_EQUAL_INT(0, ndn_data_get_metainfo(&data1, &meta));
    TEST_ASSERT_EQUAL_INT(NDN_CONTENT_TYPE_BLOB, meta.content_type);
    TEST_ASSERT_EQUAL_INT(-1, meta.freshness);
}

static void test_ndn_data_get_content__valid(void)
{
    uint8_t buf[] = {
	NDN_TLV_DATA, 75,
	NDN_TLV_NAME, 12,
	NDN_TLV_NAME_COMPONENT, 1, 'a',
	NDN_TLV_NAME_COMPONENT, 1, 'b',
	NDN_TLV_NAME_COMPONENT, 1, 'c',
	NDN_TLV_NAME_COMPONENT, 1, 'd',
	NDN_TLV_METAINFO, 9,
	NDN_TLV_CONTENT_TYPE, 1, NDN_CONTENT_TYPE_BLOB,
	NDN_TLV_FRESHNESS_PERIOD, 4, 7, 0x10, 0x20, 0x34,
	NDN_TLV_CONTENT, 9,
	0x91, 0x82, 0x73, 0x64, 0x55, 0x44, 0x33, 0x22, 0x10,
	NDN_TLV_SIGNATURE_INFO, 3,
	NDN_TLV_SIGNATURE_TYPE, 1, NDN_SIG_TYPE_DIGEST_SHA256,
	NDN_TLV_SIGNATURE_VALUE, 32,
	0xe3, 0x8f, 0x85, 0x5b, 0x51, 0x7f, 0x42, 0xa6, 0x4f, 0x5a, 0x34,
	0x38, 0x00, 0x0b, 0x2b, 0x34, 0xa5, 0x85, 0x1c, 0xc9, 0x97, 0xf2,
	0x0c, 0x8c, 0x55, 0x28, 0xf5, 0xaf, 0xc0, 0xc2, 0x58, 0x54,
    };

    ndn_block_t data = { buf, sizeof(buf) };

    ndn_block_t content;
    uint8_t result[] = {
	NDN_TLV_CONTENT, 9,
	0x91, 0x82, 0x73, 0x64, 0x55, 0x44, 0x33, 0x22, 0x10,
    };
    TEST_ASSERT_EQUAL_INT(0, ndn_data_get_content(&data, &content));
    TEST_ASSERT(0 == memcmp(result, content.buf, content.len));
}

static void test_ndn_data_get_key_locator__all(void)
{
    uint8_t buf1[] = {
	NDN_TLV_DATA, 75,
	NDN_TLV_NAME, 12,
	NDN_TLV_NAME_COMPONENT, 1, 'a',
	NDN_TLV_NAME_COMPONENT, 1, 'b',
	NDN_TLV_NAME_COMPONENT, 1, 'c',
	NDN_TLV_NAME_COMPONENT, 1, 'd',
	NDN_TLV_METAINFO, 9,
	NDN_TLV_CONTENT_TYPE, 1, NDN_CONTENT_TYPE_BLOB,
	NDN_TLV_FRESHNESS_PERIOD, 4, 7, 0x10, 0x20, 0x34,
	NDN_TLV_CONTENT, 9,
	0x91, 0x82, 0x73, 0x64, 0x55, 0x44, 0x33, 0x22, 0x10,
	NDN_TLV_SIGNATURE_INFO, 3,
	NDN_TLV_SIGNATURE_TYPE, 1, NDN_SIG_TYPE_DIGEST_SHA256,
	NDN_TLV_SIGNATURE_VALUE, 32,
	0xe3, 0x8f, 0x85, 0x5b, 0x51, 0x7f, 0x42, 0xa6, 0x4f, 0x5a, 0x34,
	0x38, 0x00, 0x0b, 0x2b, 0x34, 0xa5, 0x85, 0x1c, 0xc9, 0x97, 0xf2,
	0x0c, 0x8c, 0x55, 0x28, 0xf5, 0xaf, 0xc0, 0xc2, 0x58, 0x54,
    };

    ndn_block_t data1 = { buf1, sizeof(buf1) };
    ndn_block_t key_name;

    TEST_ASSERT_EQUAL_INT(-2, ndn_data_get_key_locator(&data1, &key_name));

    uint8_t buf2[119] = {
	NDN_TLV_DATA, 117,
	NDN_TLV_NAME, 12,
	NDN_TLV_NAME_COMPONENT, 1, 'a',
	NDN_TLV_NAME_COMPONENT, 1, 'b',
	NDN_TLV_NAME_COMPONENT, 1, 'c',
	NDN_TLV_NAME_COMPONENT, 1, 'd',
	NDN_TLV_METAINFO, 9,
	NDN_TLV_CONTENT_TYPE, 1, NDN_CONTENT_TYPE_BLOB,
	NDN_TLV_FRESHNESS_PERIOD, 4, 7, 0x10, 0x20, 0x34,
	NDN_TLV_CONTENT, 9,
	0x91, 0x82, 0x73, 0x64, 0x55, 0x44, 0x33, 0x22, 0x10,
	NDN_TLV_SIGNATURE_INFO, 13,
	NDN_TLV_SIGNATURE_TYPE, 1, NDN_SIG_TYPE_ECDSA_SHA256,
	NDN_TLV_KEY_LOCATOR, 8, NDN_TLV_NAME, 6,
	NDN_TLV_NAME_COMPONENT, 1, 'a',
	NDN_TLV_NAME_COMPONENT, 1, 'b',
	NDN_TLV_SIGNATURE_VALUE, 64,
    };

    ndn_block_t data2 = { buf2, sizeof(buf2) };
    uint8_t result2[] = {
	NDN_TLV_NAME, 6,
	NDN_TLV_NAME_COMPONENT, 1, 'a',
	NDN_TLV_NAME_COMPONENT, 1, 'b',
    };

    TEST_ASSERT_EQUAL_INT(0, ndn_data_get_key_locator(&data2, &key_name));
    TEST_ASSERT_EQUAL_INT(sizeof(result2), key_name.len);
    TEST_ASSERT(0 == memcmp(result2, key_name.buf, sizeof(result2)));
}

static void test_ndn_data_verify_signature__all(void)
{
    uint8_t buf[109] = {
	NDN_TLV_DATA, 75,
	NDN_TLV_NAME, 12,
	NDN_TLV_NAME_COMPONENT, 1, 'a',
	NDN_TLV_NAME_COMPONENT, 1, 'b',
	NDN_TLV_NAME_COMPONENT, 1, 'c',
	NDN_TLV_NAME_COMPONENT, 1, 'd',
	NDN_TLV_METAINFO, 9,
	NDN_TLV_CONTENT_TYPE, 1, NDN_CONTENT_TYPE_BLOB,
	NDN_TLV_FRESHNESS_PERIOD, 4, 7, 0x10, 0x20, 0x34,
	NDN_TLV_CONTENT, 9,
	0x91, 0x82, 0x73, 0x64, 0x55, 0x44, 0x33, 0x22, 0x10,
	NDN_TLV_SIGNATURE_INFO, 3,
	NDN_TLV_SIGNATURE_TYPE, 1, NDN_SIG_TYPE_DIGEST_SHA256,
	NDN_TLV_SIGNATURE_VALUE, 32,
	0xe3, 0x8f, 0x85, 0x5b, 0x51, 0x7f, 0x42, 0xa6, 0x4f, 0x5a, 0x34,
	0x38, 0x00, 0x0b, 0x2b, 0x34, 0xa5, 0x85, 0x1c, 0xc9, 0x97, 0xf2,
	0x0c, 0x8c, 0x55, 0x28, 0xf5, 0xaf, 0xc0, 0xc2, 0x58, 0x54,
    };

    ndn_block_t data = { buf, sizeof(buf) };

    TEST_ASSERT_EQUAL_INT(0, ndn_data_verify_signature(&data, NULL, 0));

    buf[70] = 0x33;
    TEST_ASSERT_EQUAL_INT(-1, ndn_data_verify_signature(&data, NULL, 0));

    unsigned char key[] = { 0xa1, 0xb9, 0xc8, 0xd7, 0xe0, 0xf3, 0xf2, 0xe4 };
    buf[42] = NDN_SIG_TYPE_HMAC_SHA256;
    hmac_sha256(key, sizeof(key), (const unsigned*)(buf + 2), 41, buf + 45);

    TEST_ASSERT_EQUAL_INT(-1, ndn_data_verify_signature(&data, NULL, 0));
    TEST_ASSERT_EQUAL_INT(0, ndn_data_verify_signature(&data, key,
						       sizeof(key)));
    buf[70] = 0;
    TEST_ASSERT_EQUAL_INT(-1, ndn_data_verify_signature(&data, key,
							sizeof(key)));

    uint8_t ecc_key_pri[] = { 0x38, 0x67, 0x54, 0x73, 0x8B, 0x72, 0x4C, 0xD6,
			      0x3E, 0xBD, 0x52, 0xF3, 0x64, 0xD8, 0xF5, 0x7F,
			      0xB5, 0xE6, 0xF2, 0x9F, 0xC2, 0x7B, 0xD6, 0x90,
			      0x42, 0x9D, 0xC8, 0xCE, 0xF0, 0xDE, 0x75, 0xB3 };
    uint8_t ecc_key_pub[] = { 0x2C, 0x3C, 0x18, 0xCB, 0x31, 0x88, 0x0B, 0xC3,
			      0x73, 0xF4, 0x4A, 0xD4, 0x3F, 0x8C, 0x80, 0x24,
			      0xD4, 0x8E, 0xBE, 0xB4, 0xAD, 0xF0, 0x69, 0xA6,
			      0xFE, 0x29, 0x12, 0xAC, 0xC1, 0xE1, 0x26, 0x7E,
			      0x2B, 0x25, 0x69, 0x02, 0xD5, 0x85, 0x51, 0x4B,
			      0x91, 0xAC, 0xB9, 0xD1, 0x19, 0xE9, 0x5E, 0x97,
			      0x20, 0xBB, 0x16, 0x2A, 0xD3, 0x2F, 0xB5, 0x11,
			      0x1B, 0xD1, 0xAF, 0x76, 0xDB, 0xAD, 0xB8, 0xCE };

    buf[1] += 32;
    buf[42] = NDN_SIG_TYPE_ECDSA_SHA256;
    buf[44] = 64;
    uECC_Curve curve = uECC_secp256r1();
    uint8_t h[32] = {0};
    sha256(buf + 2, 41, h);
    TEST_ASSERT(uECC_sign(ecc_key_pri, h, sizeof(h), buf + 45, curve) != 0);
    TEST_ASSERT_EQUAL_INT(0, ndn_data_verify_signature(&data, ecc_key_pub,
						       sizeof(ecc_key_pub)));
    buf[70] = 0;
    TEST_ASSERT_EQUAL_INT(-1, ndn_data_verify_signature(&data, ecc_key_pub,
							sizeof(ecc_key_pub)));
}

static void test_ndn_data_ccm__all(void)
{
    uint8_t key[] = { 0xa1, 0xb9, 0xc8, 0xd7, 0xe0, 0xf3, 0xf2, 0xe4,
		      0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22 };

    const char* str = "/a/b/c/d";
    ndn_shared_block_t* sn = ndn_name_from_uri(str, strlen(str));
    TEST_ASSERT_NOT_NULL(sn);

    uint8_t con[] = { 0x91, 0x82, 0x73, 0x64, 0x55, 0x44, 0x33, 0x22, 0x10 };
    ndn_block_t content;
    content.buf = con;
    content.len = sizeof(con);

    ndn_shared_block_t* sd =
        ndn_data_encrypt_with_ccm(&sn->block, &content, key, sizeof(key));
    TEST_ASSERT_NOT_NULL(sd);

    ndn_shared_block_t* sc =
        ndn_data_decrypt_with_ccm(&sd->block, key, sizeof(key));
    TEST_ASSERT_NOT_NULL(sc);

    TEST_ASSERT_EQUAL_INT(sizeof(con), sc->block.len);
    TEST_ASSERT(0 == memcmp(sc->block.buf, con, sizeof(con)));

    ndn_shared_block_release(sc);
    ndn_shared_block_release(sd);
    ndn_shared_block_release(sn);
}

/* static void test_ndn_data_ecc_try(void) */
/* { */
/*     uint8_t private[32] = {0}; */
/*     uint8_t public[64] = {0}; */

/*     uECC_Curve curve = uECC_secp256r1(); */
/*     if (!uECC_make_key(public, private, curve)) { */
/* 	printf("uECC_make_key() failed\n"); */
/*     } */

/*     printf("\nprivate:\n"); */
/*     for (size_t i = 0; i < sizeof(private); ++i) { */
/* 	printf("0x%02X, ", private[i]); */
/*     } */

/*     printf("\npublic:\n"); */
/*     for (size_t i = 0; i < sizeof(public); ++i) { */
/* 	printf("0x%02X, ", public[i]); */
/*     } */
/* } */

Test *tests_ndn_encoding_data_tests(void)
{
    EMB_UNIT_TESTFIXTURES(fixtures) {
        new_TestFixture(test_ndn_data_create__no_keylocator),
        new_TestFixture(test_ndn_data_create__with_keylocator),
	new_TestFixture(test_ndn_data_create2__no_keylocator),
	new_TestFixture(test_ndn_data_create2__with_keylocator),
	new_TestFixture(test_ndn_data_get_name__valid),
	new_TestFixture(test_ndn_data_get_metainfo__valid),
	new_TestFixture(test_ndn_data_get_content__valid),
	new_TestFixture(test_ndn_data_get_key_locator__all),
        new_TestFixture(test_ndn_data_verify_signature__all),
        new_TestFixture(test_ndn_data_ccm__all),
	    //new_TestFixture(test_ndn_data_ecc_try),
    };

    EMB_UNIT_TESTCALLER(ndn_encoding_data_tests, NULL, NULL, fixtures);

    return (Test *)&ndn_encoding_data_tests;
}

void tests_ndn_encoding(void)
{
    TESTS_RUN(tests_ndn_encoding_block_tests());
    TESTS_RUN(tests_ndn_encoding_name_tests());
    TESTS_RUN(tests_ndn_encoding_interest_tests());
    TESTS_RUN(tests_ndn_encoding_metainfo_tests());
    TESTS_RUN(tests_ndn_encoding_data_tests());
}
/** @} */
