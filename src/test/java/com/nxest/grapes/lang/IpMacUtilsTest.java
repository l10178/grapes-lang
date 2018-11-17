package com.nxest.grapes.lang;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static com.nxest.grapes.lang.IpMacUtils.INVALID_VALUE;
import static org.junit.jupiter.api.Assertions.*;

/**
 * IpMacUtils Test
 */
class IpMacUtilsTest {

    private static final String IP_TEST_STR = "192.168.0.1";
    private static final long IP_TEST_LONG = 3232235521L;

    private static final String IPV6_TEST_STR = "ff06:0:0:0:0:0:0:c3";
    private static final BigInteger IPV6_TEST_NUM = new BigInteger("338984292706304756556241983349463187651");
    private static final String IPV6_TEST_STR_SHORT = "ff06::c3";

    private static final String MAC_TEST_STR = "60:a0:10:50:d0:30";
    private static final long MAC_TEST_NUM = 106240584765488L;

    @Test
    void ipV4ToLong() {
        assertEquals(IP_TEST_LONG, IpMacUtils.ipV4ToLong(IP_TEST_STR));
        assertEquals(INVALID_VALUE, IpMacUtils.ipV4ToLong("256.168.0.1"));
    }

    @Test
    void longToIpV4() {
        assertEquals(IP_TEST_STR, IpMacUtils.longToIpV4(IP_TEST_LONG));
        assertEquals("0.0.0.0", IpMacUtils.longToIpV4(0L));
    }

    @Test
    void isLegalIpV4() {
        assertTrue(IpMacUtils.isLegalIpV4(IP_TEST_STR));
        assertFalse(IpMacUtils.isLegalIpV4(null));
        assertFalse(IpMacUtils.isLegalIpV4(" "));
        assertFalse(IpMacUtils.isLegalIpV4("a.b.d.e"));
        assertFalse(IpMacUtils.isLegalIpV4("192.0."));
        assertFalse(IpMacUtils.isLegalIpV4("256.1.2.3"));
        assertFalse(IpMacUtils.isLegalIpV4("fe80::6942:2fda:2942:24d2%10"));
    }

    @Test
    void getClassOfIp() {

        assertEquals(IpClassEnum.A, IpMacUtils.getClassOfIp("0.0.0.0"));
        assertEquals(IpClassEnum.A, IpMacUtils.getClassOfIp("120.123.124.125"));
        assertEquals(IpClassEnum.A, IpMacUtils.getClassOfIp("127.0.0.1"));
        assertEquals(IpClassEnum.A, IpMacUtils.getClassOfIp("127.255.255.255"));

        assertEquals(IpClassEnum.B, IpMacUtils.getClassOfIp("128.0.0.0"));
        assertEquals(IpClassEnum.B, IpMacUtils.getClassOfIp("129.123.124.125"));
        assertEquals(IpClassEnum.B, IpMacUtils.getClassOfIp("191.255.255.255"));

        assertEquals(IpClassEnum.C, IpMacUtils.getClassOfIp("192.0.0.0"));
        assertEquals(IpClassEnum.C, IpMacUtils.getClassOfIp("200.123.124.125"));
        assertEquals(IpClassEnum.C, IpMacUtils.getClassOfIp("223.255.255.255"));

        assertEquals(IpClassEnum.D, IpMacUtils.getClassOfIp("224.0.0.0"));
        assertEquals(IpClassEnum.D, IpMacUtils.getClassOfIp("225.123.124.125"));
        assertEquals(IpClassEnum.D, IpMacUtils.getClassOfIp("239.255.255.255"));

        assertEquals(IpClassEnum.E, IpMacUtils.getClassOfIp("240.0.0.0"));
        assertEquals(IpClassEnum.E, IpMacUtils.getClassOfIp("241.123.124.125"));
        assertEquals(IpClassEnum.E, IpMacUtils.getClassOfIp("255.255.255.255"));

    }

    @Test
    void compareIpV4() {
        assertEquals(0, IpMacUtils.compareIpV4("0.0.0.0", "0.0.0.0"));
        assertEquals(0, IpMacUtils.compareIpV4("255.255.255.255", "255.255.255.255"));
        assertEquals(0, IpMacUtils.compareIpV4("192.168.0.1", "192.168.0.1"));
        assertEquals(-1, IpMacUtils.compareIpV4("192.168.0.1", "192.168.0.2"));
        assertEquals(-256, IpMacUtils.compareIpV4("192.168.1.0", "192.168.2.0"));
        assertEquals(-65536, IpMacUtils.compareIpV4("192.168.1.1", "192.169.1.1"));
        assertEquals(-16842752, IpMacUtils.compareIpV4("192.168.1.1", "193.169.1.1"));
        assertEquals(256, IpMacUtils.compareIpV4("192.168.3.0", "192.168.2.0"));
    }

    @Test
    void ipV6toBigInteger() {
        assertEquals(IPV6_TEST_NUM, IpMacUtils.ipV6toBigInteger(IPV6_TEST_STR));
        assertEquals(IPV6_TEST_NUM, IpMacUtils.ipV6toBigInteger(IPV6_TEST_STR_SHORT));
        assertEquals(BigInteger.valueOf(INVALID_VALUE), IpMacUtils.ipV6toBigInteger(""));
    }

    @Test
    void bigIntegerToIpV6() {
        assertEquals(IPV6_TEST_STR_SHORT, IpMacUtils.bigIntegerToIpV6(IPV6_TEST_NUM));
    }

    @Test
    void isLegalIpV6() {
        assertTrue(IpMacUtils.isLegalIpV6(IPV6_TEST_STR));
        assertTrue(IpMacUtils.isLegalIpV6(IPV6_TEST_STR_SHORT));
        assertTrue(IpMacUtils.isLegalIpV6("2001:0000:3238:DFE1:0063:0000:0000:FEFB"));
        assertTrue(IpMacUtils.isLegalIpV6("2001:0000:3238:DFE1:63:0000:0000:FEFB"));
        assertTrue(IpMacUtils.isLegalIpV6("2001:0:3238:DFE1:63::FEFB"));

        // yeah ,it not legal IPV6, may be this's a bad idea.
        assertFalse(IpMacUtils.isLegalIpV6("0:0:0:0:0:ffff:192.1.56.10"));

        assertFalse(IpMacUtils.isLegalIpV6(""));
        assertFalse(IpMacUtils.isLegalIpV6("2001:0:3238:DFE1:63:::FEFB"));
        assertFalse(IpMacUtils.isLegalIpV6("GFEA:0:3238:DFE1:63::FEFB"));
    }

    @Test
    void compareIpV6() {
        assertEquals(BigInteger.ZERO, IpMacUtils.compareIpV6(IPV6_TEST_STR, IPV6_TEST_STR_SHORT));
        assertEquals(BigInteger.ONE, IpMacUtils.compareIpV6("ff06::c4", "ff06::c3"));
        assertEquals(BigInteger.valueOf(65536), IpMacUtils.compareIpV6("ff06:0:0:0:0:0:1:c3", "ff06::c3"));
    }

    @Test
    void macToLong() {
        assertEquals(MAC_TEST_NUM, IpMacUtils.macToLong(MAC_TEST_STR));
        assertEquals(IpMacUtils.macToLong(MAC_TEST_STR), IpMacUtils.macToLong(MAC_TEST_STR.toUpperCase()));
        assertEquals(MAC_TEST_NUM, IpMacUtils.macToLong(MAC_TEST_STR.replace(':', '-')));
    }

    @Test
    void longToMac() {
        assertEquals(MAC_TEST_STR.replace(':', '-'), IpMacUtils.longToMac(MAC_TEST_NUM));
    }

    @Test
    void isLegalMac() {
        assertTrue(IpMacUtils.isLegalMac(MAC_TEST_STR));
        assertTrue(IpMacUtils.isLegalMac(MAC_TEST_STR.toUpperCase()));
        assertTrue(IpMacUtils.isLegalMac(MAC_TEST_STR.replace(':', '-')));

        assertFalse(IpMacUtils.isLegalMac(""));
        assertFalse(IpMacUtils.isLegalMac("12:34::"));
        assertFalse(IpMacUtils.isLegalMac("GG:a0:10:50:d0:30"));
    }

    @Test
    void rangeBetweenIpV4() {
        assertEquals(1, IpMacUtils.rangeBetweenIpV4("192.168.0.1", "192.168.0.2"));
        assertEquals(256, IpMacUtils.rangeBetweenIpV4("192.168.0.1", "192.168.1.1"));
    }

    @Test
    void rangeBetweenIpV6() {
        assertEquals(BigInteger.ONE, IpMacUtils.rangeBetweenIpV6("ff06::c3", "ff06::c4"));
        assertEquals(BigInteger.valueOf(65536), IpMacUtils.rangeBetweenIpV6("ff06::c3", "ff06:0:0:0:0:0:1:c3"));
        assertEquals(BigInteger.valueOf(-65536), IpMacUtils.rangeBetweenIpV6("ff06:0:0:0:0:0:1:c3", "ff06::c3"));
    }

    @Test
    void ipExistsInRange() {
        assertTrue(IpMacUtils.ipExistsInRange("192.168.1.2", "192.168.1.2", null));
        assertTrue(IpMacUtils.ipExistsInRange("192.168.1.2", "192.168.1.2", "192.168.1.5"));
        assertTrue(IpMacUtils.ipExistsInRange("192.168.1.5", "192.168.1.2", "192.168.1.5"));
        assertTrue(IpMacUtils.ipExistsInRange("ff06:0:0:0:0:1:0:c3", "ff06::c3", "ff06:0:0:0:0:2:0:c3"));
        assertFalse(IpMacUtils.ipExistsInRange("192.168.1.2", "192.168.1.3", "192.168.1.5"));
        assertFalse(IpMacUtils.ipExistsInRange("192.168.1.2", null, null));
        assertFalse(IpMacUtils.ipExistsInRange("192.168.1.2", "192.168.1.3", "ff06::c3"));

    }

    @Test
    void ipExistsInRangeSection() {
        assertTrue(IpMacUtils.ipExistsInRange("192.168.1.2", "192.168.1.2"));
        assertTrue(IpMacUtils.ipExistsInRange("192.168.1.2", "192.168.1.2- 192.168.1.5"));
        assertTrue(IpMacUtils.ipExistsInRange("192.168.1.5", "192.168.1.2 - 192.168.1.5 "));
        assertFalse(IpMacUtils.ipExistsInRange("192.168.1.2", null));
        assertFalse(IpMacUtils.ipExistsInRange("192.168.1.2", "192.168.1.3-ff06::c3"));
    }

    @Test
    void macExistsInArray() {
        assertTrue(IpMacUtils.macExistsInArray("60:a0:10:50:d0:30", "60:a0:10:50:d0:30", "50:a0:10:50:d0:30"));
        assertTrue(IpMacUtils.macExistsInArray("60:a0:10:50:d0:30", "60-A0-10-50-D0-30"));
        assertFalse(IpMacUtils.macExistsInArray("60:a0:10:50:d0:30", ""));
    }
    @Test
    void macExistsInRange() {
        assertTrue(IpMacUtils.macExistsInRange("60:a0:10:50:d0:30", "60:a0:10:50:d0:30", "70-A0-10-50-D0-30"));
        assertTrue(IpMacUtils.macExistsInRange("60:a0:10:50:d0:30", "50:a0:10:50:d0:30", "70-A0-10-50-D0-30"));
    }
}
