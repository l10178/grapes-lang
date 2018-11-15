package com.nxest.grapes.lang;

import java.math.BigInteger;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * A collection of IP and MAC utilities.
 *
 * @author l10178
 */
public class IpMacUtils {

    private static final String IPV4_REGEX = "(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\\x2e){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])";
    private static final Pattern IPV4_PATTERN = Pattern.compile(IPV4_REGEX);
    private static final Pattern MAC6 = Pattern.compile("([a-fA-F0-9]{1,2}[-:]){5}[a-fA-F0-9]{1,2}");

    /**
     * default value for invalid IP
     */
    public static final long IP_INVALID = -1L;

    /**
     * dot <code>.</code> value.
     */
    private static final String DOT = "\\x2e";
    /**
     * colon <code>:</code> value.
     */
    private static final String COLON = ":";

    private static final String SLASH = "/";

    private static final String MIDLINE = "-";

    private IpMacUtils() {
    }

    /**
     * convert string IPV4 to long.
     * 
     * <pre>
     *     192.168.0.1 to 3232235521L
     * </pre>
     *
     * @param hostIp ip address
     * @return the long value,if ip is invalid, will return 0L
     */
    public static long ipV4ToLong(final String hostIp) {
        if (!isLegalIpV4(hostIp)) {
            return IP_INVALID;
        }
        String[] parts = hostIp.trim().split(DOT);
        long ipLong = 0L;
        for (final String part : parts) {
            ipLong = ipLong << 8 | Long.valueOf(part);
        }
        return ipLong;
    }

    /**
     * convert long IPV4 to string.
     * 
     * <pre>
     *     3232235521L to 192.168.0.1
     * </pre>
     *
     * @param longIp IP long value
     * @return IP string value
     */
    public static String longToIpV4(long longIp) {
        if (longIp < 0) {
            throw new IllegalArgumentException("IP can not be negative.");
        }
        return (longIp >> 24 & 255L) + "." + (longIp >> 16 & 255L) + "." + (longIp >> 8 & 255L) + "." + (longIp & 255L);
    }

    /**
     * Checks if legal IPV4.
     * 
     * <pre>
     * assertTrue(IpMacUtils.isLegalIpV4("192.168.0.1"));
     * assertFalse(IpMacUtils.isLegalIpV4(null));
     * assertFalse(IpMacUtils.isLegalIpV4(" "));
     * assertFalse(IpMacUtils.isLegalIpV4("a.b.d.e"));
     * assertFalse(IpMacUtils.isLegalIpV4("192.0."));
     * assertFalse(IpMacUtils.isLegalIpV4("256.1.2.3"));
     * </pre>
     *
     * @param ip the ip to check, may be null
     * @return {@code true} if legal IPV4
     */
    public static boolean isLegalIpV4(final String ip) {
        if (isBlank(ip)) {
            return false;
        }
        return IPV4_PATTERN.matcher(ip.trim()).matches();
    }

    /**
     * Get IPV4 class type, A B C D E
     *
     * <pre>
     *     "A", "0.0.0.0-127.255.255.255"
     *     "B", "128.0.0.0–191.255.255.255"
     *     "C", "192.0.0.0–223.255.255.255"
     *     "D", "224.0.0.0–239.255.255.255"
     *     "E", "240.0.0.0–255.255.255.255"
     * </pre>
     *
     * @param ipv4 the IP to check,should be legal IP
     * @return Ip class
     * @throws IllegalArgumentException throw if not legal IP
     */
    public static IpClassEnum getClassOfIp(final String ipv4) throws IllegalArgumentException {
        if (!isLegalIpV4(ipv4)) {
            throw new IllegalArgumentException("Illegal arguments : " + ipv4);
        }
        String[] ipSegs = ipv4.split(DOT);
        String ipSeg = ipSegs[0];
        int ipSegDigit = Integer.parseInt(ipSeg);
        StringBuilder binStr = new StringBuilder(Integer.toBinaryString(ipSegDigit));
        String tmpStr = binStr.toString();

        for (int binaryChars = 0; binaryChars < 8 - tmpStr.length(); ++binaryChars) {
            binStr.insert(0, "0");
        }

        char[] binArr = binStr.toString().toCharArray();
        if (binArr.length == 8) {
            if (48 == binArr[0]) {
                return IpClassEnum.A;
            }

            if (49 == binArr[0] && 48 == binArr[1]) {
                return IpClassEnum.B;
            }

            if (49 == binArr[0] && 49 == binArr[1] && 48 == binArr[2]) {
                return IpClassEnum.C;
            }

            if (49 == binArr[0] && 49 == binArr[1] && 49 == binArr[2] && 48 == binArr[3]) {
                return IpClassEnum.D;
            }

            if (49 == binArr[0] && 49 == binArr[1] && 49 == binArr[2] && 49 == binArr[3]) {
                return IpClassEnum.E;
            }
        }
        throw new IllegalArgumentException("Illegal arguments : " + ipv4);
    }

    /**
     * compare IPV4
     *
     * @param leftIp  ip1
     * @param rightIp ip2
     * @return leftIp long value - rightIp long value
     */
    public static long compareIpV4(final String leftIp, String rightIp) {
        return ipV4ToLong(leftIp) - ipV4ToLong(rightIp);
    }

    /**
     * The range between two V4 IPs.
     *
     * @param startIp the start IP
     * @param endIp   the end IP
     * @return endIp - startIp
     */
    public static long rangeBetweenIpV4(final String startIp, final String endIp) {
        return ipV4ToLong(endIp) - ipV4ToLong(startIp);
    }

    /**
     * The range between two V6 IPs.
     *
     * @param startIp the start IP
     * @param endIp   the end IP
     * @return endIp - startIp
     */
    public static BigInteger rangeBetweenIpV6(final String startIp, final String endIp) {
        return ipV6toBigInteger(endIp).subtract(ipV6toBigInteger(startIp));
    }

    /**
     * convert String IPV6 to BigInteger
     *
     * @param ipv6 ipv6 string value
     * @return ipv6 BigInteger value
     */
    public static BigInteger ipV6toBigInteger(final String ipv6) {
        if (!isLegalIpV6(ipv6)) {
            return BigInteger.valueOf(IP_INVALID);
        }
        return ipV6toBigIntegerSum(ipv6);
    }

    private static BigInteger ipV6toBigIntegerSum(final String ipv6) {
        int compressIndex = ipv6.indexOf("::");
        if (compressIndex != -1) {
            String part1s = ipv6.substring(0, compressIndex);
            String part2s = ipv6.substring(compressIndex + 1);
            BigInteger part1 = ipV6toBigIntegerSum(part1s);
            BigInteger part2 = ipV6toBigIntegerSum(part2s);
            int part1hasDot = 0;
            char ch[] = part1s.toCharArray();
            for (char c : ch) {
                if (c == ':') {
                    part1hasDot++;
                }
            }
            return part1.shiftLeft(16 * (7 - part1hasDot)).add(part2);
        }
        String[] str = ipv6.split(COLON);
        BigInteger big = BigInteger.ZERO;
        for (int i = 0; i < str.length; i++) {
            // ::1
            if (str[i].isEmpty()) {
                str[i] = "0";
            }
            big = big.add(BigInteger.valueOf(Long.valueOf(str[i], 16)).shiftLeft(16 * (str.length - i - 1)));
        }
        return big;
    }

    /**
     * convert BigInteger IPV6 to String
     *
     * @param big ipv6 BigInteger value
     * @return ipv6 String value
     */
    public static String bigIntegerToIpV6(BigInteger big) {
        StringBuilder str = new StringBuilder();
        BigInteger ff = BigInteger.valueOf(0xffff);
        for (int i = 0; i < 8; i++) {
            str.insert(0, big.and(ff).toString(16) + COLON);

            big = big.shiftRight(16);
        }
        // the last :
        str = new StringBuilder(str.substring(0, str.length() - 1));

        return str.toString().replaceFirst("(^|:)(0+(:|$)){2,8}", "::");
    }

    /**
     * compare two IPV6
     *
     * @param leftIp  ip1
     * @param rightIp ip2
     * @return leftIp - rightIp
     */
    public static BigInteger compareIpV6(final String leftIp, final String rightIp) {
        return ipV6toBigInteger(leftIp).subtract(ipV6toBigInteger(rightIp));
    }

    /**
     * convert string mac to long
     * 
     * <pre>
     *      60-a0-10-50-d0-30 to 106240584765488L
     * </pre>
     *
     * @param mac mac string
     * @return long value
     */
    public static long macToLong(final String mac) {
        if (!isLegalMac(mac)) {
            return IP_INVALID;
        }
        String macAddr = mac.replace(MIDLINE, "");
        macAddr = macAddr.replace(COLON, "");
        long longMac = 0L;

        for (int i = 0; i < macAddr.length(); ++i) {
            if (i != 0) {
                longMac <<= 4;
            }

            if (macAddr.charAt(i) >= 48 && macAddr.charAt(i) <= 57) {
                longMac += (long) (macAddr.charAt(i) - 48);
            } else if (macAddr.charAt(i) >= 97 && macAddr.charAt(i) <= 102) {
                longMac += (long) (macAddr.charAt(i) - 97 + 10);
            } else if (macAddr.charAt(i) >= 65 && macAddr.charAt(i) <= 70) {
                longMac += (long) (macAddr.charAt(i) - 65 + 10);
            }
        }

        return longMac;
    }

    /**
     * convert long mac to string
     * 
     * <pre>
     *     106240584765488L to 60-a0-10-50-d0-30
     * </pre>
     *
     * @param longMac mac long value
     * @return string value
     */
    public static String longToMac(long longMac) {
        char[] strArray = new char[12];

        for (int sb = 11; sb >= 0; --sb) {
            char i = (char) ((int) (longMac & 15L));
            if (i >= 10) {
                i = (char) (i - 10 + 97);
            } else {
                i = (char) (i + 48);
            }

            strArray[sb] = i;
            if (sb > 0) {
                longMac >>= 4;
            }
        }

        StringBuilder mac = new StringBuilder();
        for (int i = 0; i < strArray.length; ++i) {
            mac.append(strArray[i]);
            if (i != strArray.length - 1 && (i + 1) % 2 == 0) {
                mac.append(MIDLINE);
            }
        }

        return mac.toString();
    }

    /**
     * Checks if legal MAC
     * 
     * <pre>
     * assertTrue(IpMacUtils.isLegalMac("60:a0:10:50:d0:30"));
     * assertTrue(IpMacUtils.isLegalMac("60:A0:10:50:D0:30"));
     * assertTrue(IpMacUtils.isLegalMac(60 - a0 - 10 - 50 - d0 - 30));
     * assertFalse(IpMacUtils.isLegalMac(""));
     * assertFalse(IpMacUtils.isLegalMac("12:34::"));
     * assertFalse(IpMacUtils.isLegalMac("GG:a0:10:50:d0:30"));
     * </pre>
     *
     * @param mac the mac to check
     * @return {@code true} if legal MAC
     */
    public static boolean isLegalMac(final String mac) {
        return isNotBlank(mac) && MAC6.matcher(mac.trim()).matches();
    }

    public static boolean isSameIpType(final String me, String he) {
        boolean meIsV4 = isLegalIpV4(me);
        boolean meIsV6 = isLegalIpV6(me);
        boolean heIsV4 = isLegalIpV4(he);
        boolean heIsV6 = isLegalIpV6(he);
        boolean isAllIpv4 = meIsV4 && heIsV4;
        boolean isAllIpv6 = meIsV6 && heIsV6;
        return isAllIpv4 || isAllIpv6;
    }

    public static long compareIp(final String leftIp, String rightIp) {
        if (isLegalIpV4(leftIp) && isLegalIpV4(rightIp)) {
            return compareIpV4(leftIp, rightIp);
        } else if (isLegalIpV6(leftIp) && isLegalIpV6(rightIp)) {
            return compareIpV6(leftIp, rightIp).longValue();
        } else {
            throw new NumberFormatException(leftIp + " and " + rightIp + " are not same IP type.");
        }
    }

    public static boolean isLegalIpV6(final String ipv6) {
        return isLegalIpV6Common(ipv6) || isLegalIPV6Compatible(ipv6);
    }

    public static boolean isLegalIpV6Common(final String ip) {
        try {
            InetAddress e = Inet6Address.getByName(ip);
            return e instanceof Inet6Address;
        } catch (Exception e) {
            return false;
        }
    }

    public static boolean isLegalIpV6All(final String ip) {
        return isLegalIpV6Common(ip) || isLegalIPV6Compatible(ip) || isLegalIPV6Prefix(ip);
    }

    public static boolean isLegalIPV6Compatible(final String ip) {
        return isLegalIpV6Common(ip) && (!isBlank(ip) && countMatches(ip, ".") == 3);
    }

    public static boolean isLegalIPV6Prefix(final String ip) {
        if (isBlank(ip)) {
            return false;
        }
        if (countMatches(ip, SLASH) == 1 && !ip.endsWith(SLASH)) {
            String[] ips = ip.split(SLASH);

            int prefixLength1;
            try {
                if (ips[1].length() > 1 && ips[1].startsWith("0")) {
                    return false;
                }

                prefixLength1 = Integer.parseInt(ips[1]);
            } catch (Exception e) {
                return false;
            }

            return isLegalIpV6Common(ips[0]) && prefixLength1 >= 0 && prefixLength1 <= 128;
        }
        return false;
    }

    /**
     * check the ip in range.
     * 
     * <pre>
     * assertTrue(IpMacUtils.ipExistsInRange("192.168.1.2", "192.168.1.2"));
     * assertTrue(IpMacUtils.ipExistsInRange("192.168.1.2", "192.168.1.2- 192.168.1.5"));
     * assertTrue(IpMacUtils.ipExistsInRange("192.168.1.5", "192.168.1.2 - 192.168.1.5 "));
     * assertFalse(IpMacUtils.ipExistsInRange("192.168.1.2", null));
     * assertFalse(IpMacUtils.ipExistsInRange("192.168.1.2", "192.168.1.3-ff06::c3"));
     * </pre>
     * 
     * @param ip        the ip to compare, can not be null
     * @param ipSection ip section split by '-', eg. 192.168.1.2-192.168.3.0
     * @return true if ip in range
     */
    public static boolean ipExistsInRange(String ip, String ipSection) {
        return ipExistsInRangeBySplit(ip, ipSection, MIDLINE);
    }

    public static boolean ipExistsInRangeBySplit(String ip, String ipSection, String split) {
        if (isBlank(ip) || isBlank(ipSection)) {
            return false;
        }
        // split may be space, may be a pattern, but can not be null
        if (Objects.isNull(split)) {
            return false;
        }
        String[] ipArray = ipSection.split(split);
        String beginIp = ipArray[0].trim();
        String endIp = ipArray[0].trim();
        if (ipArray.length > 1) {
            endIp = ipArray[1].trim();
        }
        return ipExistsInRange(ip, beginIp, endIp);
    }

    /**
     * check the ip in range.
     * 
     * <pre>
     * assertTrue(IpMacUtils.ipExistsInRange("192.168.1.2", "192.168.1.2", null));
     * assertTrue(IpMacUtils.ipExistsInRange("192.168.1.2", "192.168.1.2", "192.168.1.5"));
     * assertTrue(IpMacUtils.ipExistsInRange("192.168.1.5", "192.168.1.2", "192.168.1.5"));
     * assertTrue(IpMacUtils.ipExistsInRange("ff06:0:0:0:0:1:0:c3", "ff06::c3", "ff06:0:0:0:0:2:0:c3"));
     * assertFalse(IpMacUtils.ipExistsInRange("192.168.1.2", "192.168.1.3", "192.168.1.5"));
     * assertFalse(IpMacUtils.ipExistsInRange("192.168.1.2", null, null));
     * assertFalse(IpMacUtils.ipExistsInRange("192.168.1.2", "192.168.1.3", "ff06::c3"));
     * </pre>
     * 
     * @param ip      the ip to compare, can not be null
     * @param beginIp begin ip, can not be null
     * @param endIp   end ip, can be null
     * @return true if ip in range
     */
    public static boolean ipExistsInRange(String ip, String beginIp, String endIp) {
        if (isBlank(ip) || (isBlank(beginIp) && isBlank(endIp))) {
            return false;
        }
        if (isBlank(beginIp)) {
            beginIp = endIp;
        }
        if (isBlank(endIp)) {
            endIp = beginIp;
        }
        return compareIp(ip, beginIp) >= 0 && compareIp(ip, endIp) <= 0;
    }

    private static boolean isBlank(CharSequence cs) {
        int strLen;
        if (cs != null && (strLen = cs.length()) != 0) {
            for (int i = 0; i < strLen; ++i) {
                if (!Character.isWhitespace(cs.charAt(i))) {
                    return false;
                }
            }
            return true;
        } else {
            return true;
        }
    }

    private static boolean isNotBlank(CharSequence cs) {
        return !isBlank(cs);
    }

    private static int countMatches(CharSequence str, CharSequence sub) {
        if (!isBlank(str) && !isBlank(sub)) {
            int count = 0;

            for (int idx = 0; (idx = indexOf(str, sub, idx)) != -1; idx += sub.length()) {
                ++count;
            }

            return count;
        } else {
            return 0;
        }
    }

    private static int indexOf(CharSequence cs, CharSequence searchChar, int start) {
        return cs.toString().indexOf(searchChar.toString(), start);
    }

}
