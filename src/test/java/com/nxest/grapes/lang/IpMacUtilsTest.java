package com.nxest.grapes.lang;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * IpMacUtils Test
 */
class IpMacUtilsTest {

    public static final String IP_TEST_STR = "192.168.0.1";
    public static final long IP_TEST_LONG = 3232235521L;

    @Test
    void ipV4ToLong() {
        assertEquals(IP_TEST_LONG, IpMacUtils.ipV4ToLong(IP_TEST_STR));
        assertEquals(IpMacUtils.IP_ZERO, IpMacUtils.ipV4ToLong("256.168.0.1"));
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
    void ipV6ToDouble() {
    }

    @Test
    void macToLong() {
    }

    @Test
    void longToMac() {
    }

    @Test
    void isLegalIpV4WithMask() {
    }

    @Test
    void isLegalMac() {
    }

    @Test
    void isLegalMacWithMask() {
    }

    @Test
    void isLegalMac3() {
    }

    @Test
    void isLegalMac3WithMask() {
    }

    @Test
    void formatMac() {
    }

    @Test
    void normalizeMac() {
    }

    @Test
    void isLegalMask() {
    }

    @Test
    void isSameIpType() {
    }

    @Test
    void compareIpV4() {
    }

    @Test
    void compareIpV41() {
    }

    @Test
    void compareIpV6() {
    }

    @Test
    void compareIp() {
    }

    @Test
    void rangeBetweenIpV4() {
    }

    @Test
    void rangeBetweenIpV6() {
    }

    @Test
    void isLegalIpV6() {
    }

    @Test
    void isLegalIpV6Common() {
    }

    @Test
    void isLegalIpV6All() {
    }

    @Test
    void isLegalIPV6Compatible() {
    }

    @Test
    void isLegalIPV6Prefix() {
    }

    @Test
    void getAllIpByHost() {
    }


    @Test
    void ipAddressParseUtil() {
    }

    @Test
    void convertIntToIpV4Mask() {
    }

    @Test
    void convertIpV4MaskToInt() {
    }

    @Test
    void convertIntToV6Mask() {
    }

    @Test
    void getClassOfIpAdress() {
    }

    @Test
    void getSubnetAddressForIpV4() {
    }

    @Test
    void getFirstIpAddress() {
    }

    @Test
    void getIpMaskBits() {
    }
}
