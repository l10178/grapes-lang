package com.nxest.grapes.lang;

import java.math.BigInteger;
import java.net.*;
import java.util.*;
import java.util.regex.Pattern;

/**
 * A collection of IP and MAC utilities.
 *
 * @author l10178
 */
public class IpMacUtils {

    private static final String IPV4_REGEX = "(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\\x2e){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])";
    private static final Pattern IPV4_PATTERN = Pattern.compile(IPV4_REGEX);
    private static final Pattern MAC3 = Pattern.compile("([a-fA-F0-9]{1,4}-){2}[a-fA-F0-9]{1,4}");
    private static final Pattern MAC3_WITH_MASK = Pattern.compile("([a-fA-F0-9]{1,4}-){2}[a-fA-F0-9]{1,4}/([a-fA-F0-9]{1,4}-){2}[a-fA-F0-9]{1,4}");
    private static final Pattern MAC6 = Pattern.compile("([a-fA-F0-9]{1,2}[-:]){5}[a-fA-F0-9]{1,2}");
    private static final Pattern MAC6COLON = Pattern.compile("(([a-fA-F0-9]{1,2}:){5}[a-fA-F0-9]{1,2})");
    private static final Pattern MAC6_WITH_MASK = Pattern.compile("([a-fA-F0-9]{1,2}-){5}[a-fA-F0-9]{1,2}/([a-fA-F0-9]{1,2}-){5}[a-fA-F0-9]{1,2}");


    /**
     * default value 0 for invalid IP
     */
    public static final long IP_ZERO = 0L;

    /**
     * dot <code>.</code> value.
     */
    private static final String DOT = "\\x2e";
    /**
     * colon <code>:</code> value.
     */
    private static final String COLON = ":";

    private static final String SLASH = "/";


    private IpMacUtils() {
    }


    /**
     * convert string IPV4 to long.
     * <pre>
     *     192.168.0.1 -> 3232235521L
     * </pre>
     *
     * @param hostIp ip address
     * @return the long value,if ip is invalid, will return 0L
     */
    public static long ipV4ToLong(final String hostIp) {
        if (!isLegalIpV4(hostIp)) {
            return IP_ZERO;
        }
        String[] parts = hostIp.trim().split(DOT);
        long ipLong = IP_ZERO;
        for (final String part : parts) {
            ipLong = ipLong << 8 | Long.valueOf(part);
        }
        return ipLong;
    }

    /**
     * convert long IPV4 to string.
     * <pre>
     *     3232235521L -> 192.168.0.1
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
     * @param ip1 ip1
     * @param ip2 ip2
     * @return ip2 long value - ip1 long value
     */
    public static long compareIpV4(final String ip1, String ip2) {
        return ipV4ToLong(ip2) - ipV4ToLong(ip1);
    }


    /**
     * convert String IPV6 to BigInteger
     *
     * @param ipv6 ipv6 string value
     * @return ipv6 BigInteger value
     */
    public static BigInteger ipV6toBigInteger(final String ipv6) {
        if (!isLegalIpV6(ipv6)) {
            return BigInteger.ZERO;
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
            //::1
            if (str[i].isEmpty()) {
                str[i] = "0";
            }
            big = big.add(BigInteger.valueOf(Long.valueOf(str[i], 16))
                .shiftLeft(16 * (str.length - i - 1)));
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
        //the last :
        str = new StringBuilder(str.substring(0, str.length() - 1));

        return str.toString().replaceFirst("(^|:)(0+(:|$)){2,8}", "::");
    }

    /**
     * compare two IPV6
     *
     * @param ip1 ip1
     * @param ip2 ip2
     * @return ip2 - ip1
     */
    public static BigInteger compareIpV6(final String ip1, final String ip2) {
        return ipV6toBigInteger(ip2).subtract(ipV6toBigInteger(ip1));
    }


    /**
     * convert string mac to long
     * <pre>
     *      60-a0-10-50-d0-30 -> 106240584765488L
     * </pre>
     *
     * @param mac mac string
     * @return long value
     */
    public static long macToLong(final String mac) {
        if (!isLegalMac(mac)) {
            return IP_ZERO;
        }
        String macAddr = mac.replace("-", "");
        macAddr = macAddr.replace(COLON, "");
        long longMac = IP_ZERO;

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
     * <pre>
     *     106240584765488L -> 60-a0-10-50-d0-30
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
                mac.append("-");
            }
        }

        return mac.toString();
    }

    /**
     * Checks if legal MAC
     * <pre>
     *      assertTrue(IpMacUtils.isLegalMac("60:a0:10:50:d0:30"));
     *      assertTrue(IpMacUtils.isLegalMac("60:A0:10:50:D0:30"));
     *      assertTrue(IpMacUtils.isLegalMac(60-a0-10-50-d0-30));
     *      assertFalse(IpMacUtils.isLegalMac(""));
     *      assertFalse(IpMacUtils.isLegalMac("12:34::"));
     *      assertFalse(IpMacUtils.isLegalMac("GG:a0:10:50:d0:30"));
     * </pre>
     *
     * @param mac the mac to check
     * @return {@code true} if legal MAC
     */
    public static boolean isLegalMac(final String mac) {
        return isNotBlank(mac) && MAC6.matcher(mac.trim()).matches();
    }


    public static boolean isLegalMacWithMask(final String mac) {
        return isNotBlank(mac) && MAC6_WITH_MASK.matcher(mac.trim()).matches();
    }


    public static boolean isLegalMac3(final String mac) {
        return isNotBlank(mac) && MAC3.matcher(mac.trim()).matches();
    }


    public static boolean isLegalMac3WithMask(final String mac) {
        return isNotBlank(mac) && MAC3_WITH_MASK.matcher(mac.trim()).matches();
    }

    public static String formatMac(String mac) {
        if (isBlank(mac)) {
            return mac;
        }
        mac = mac.replace("-", COLON);
        String[] macs = mac.split(COLON);
        List<String> macList = new ArrayList<>();

        for (final String tmp : macs) {
            int size = tmp.length();
            if (size > 2) {
                for (int j = 0; j < size; j += 2) {
                    if (j + 2 <= size) {
                        macList.add(tmp.substring(j, j + 2));
                    } else {
                        macList.add(tmp.substring(size - 1));
                    }
                }
            } else {
                macList.add(tmp);
            }
        }
        return join(macList, COLON);
    }

    public static String normalizeMac(final String mac) {
        if (isBlank(mac) || !MAC6COLON.matcher(mac.trim()).matches()) {
            throw new NumberFormatException(mac + " is a invalid MAC address.");
        }
        String[] macs = mac.trim().split(COLON);
        List<String> macList = new ArrayList<>();

        for (final String newMac : macs) {
            String macStr = newMac.trim();
            if (macStr.length() == 1) {
                macStr = "0" + macStr;
            }
            macList.add(macStr);
        }
        return join(macList, COLON);

    }


    public static boolean isLegalMask(final String mask) {
        if (isBlank(mask)) {
            return false;
        }
        String[] parts = mask.trim().split(DOT);
        if (mask.endsWith(".")) {
            return false;
        }
        if (parts.length != 4) {
            return false;
        }
        StringBuilder maskBinary = new StringBuilder();
        int leng = parts.length;

        for (int i = 0; i < leng; ++i) {
            String part = parts[i];
            if (part.length() > 1 && part.startsWith("0")) {
                return false;
            }

            try {
                int nfe = Integer.parseInt(part.trim());
                if (nfe < 0 || nfe > 255) {
                    return false;
                }

                String s = Integer.toBinaryString(nfe);

                for (int j = 0; j < 8 - s.length(); ++j) {
                    maskBinary.append("0");
                }

                maskBinary.append(s);
            } catch (NumberFormatException e) {
                return false;
            }
        }

        int count = 0;

        for (leng = 0; leng < maskBinary.length(); ++leng) {
            if (maskBinary.charAt(leng) == 49) {
                if (count >= 1) {
                    return false;
                }
            } else {
                ++count;
            }
        }

        return true;
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


    public static long compareIp(final String ip1, String ip2) {
        if (isLegalIpV4(ip1) && isLegalIpV4(ip2)) {
            return compareIpV4(ip1, ip2);
        } else if (isLegalIpV6(ip1) && isLegalIpV6(ip2)) {
            return compareIpV6(ip1, ip2).longValue();
        } else {
            throw new NumberFormatException(ip1 + " and " + ip2 + " are not same IP type.");
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
        } else if (countMatches(ip, SLASH) == 1 && !ip.endsWith(SLASH)) {
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
        } else {
            return false;
        }
    }

    public static String convertIntToIpV4Mask(int length) {
        if (length >= 32) {
            return "255.255.255.255";
        } else if (length <= 0) {
            return "0.0.0.0";
        } else {
            String mask = repeat('1', length) + repeat('0', 32 - length);
            List<String> list = new ArrayList<>();

            for (int i = 0; i < mask.length(); i += 8) {
                list.add(convertBinaryToDecimal(mask.substring(i, i + 8)));
            }

            return join(list, ".");
        }
    }


    public static int convertIpV4MaskToInt(final String v4Mask) {
        String[] segs = v4Mask.split(DOT);
        StringBuilder strV4 = new StringBuilder();

        for (final String seg : segs) {
            strV4.append(Integer.toBinaryString(Integer.valueOf(seg)));
        }

        return countMatches(strV4.toString(), "1");
    }

    public static String convertIntToV6Mask(int length) {
        if (length >= 128) {
            return "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff";
        } else if (length <= 0) {
            return "0:0:0:0:0:0:0:0";
        } else {
            String mask = repeat('1', length) + repeat('0', 128 - length);
            List<String> list = new ArrayList<>();

            for (int i = 0; i < mask.length(); i += 16) {
                list.add(convertBinaryToHex(mask.substring(i, i + 16)));
            }

            return join(list, COLON);
        }
    }

    private static String convertBinaryToDecimal(final String binary) {
        long result = 0L;

        for (int j = 0; j < binary.length(); ++j) {
            String s = binary.substring(j, j + 1);
            if (Integer.valueOf(s) != 0) {
                result = (long) ((double) result + Math.pow(2.0D, (double) (binary.length() - 1 - j)) * (double) Integer.valueOf(s));
            }
        }

        return String.valueOf(result);
    }

    private static String convertBinaryToHex(final String binary) {
        int result = 0;

        for (int j = 0; j < binary.length(); ++j) {
            String s = binary.substring(j, j + 1);
            if (Integer.valueOf(s) != 0) {
                result = (int) ((double) result + Math.pow(2.0D, (double) (binary.length() - 1 - j)) * (double) Integer.valueOf(s));
            }
        }

        return Integer.toHexString(result);
    }


    public static String getSubnetAddressForIpV4(final String ip, String v4Mask) {
        if (!isLegalIpV4(ip) || !isLegalIpV4(v4Mask)) {
            throw new IllegalArgumentException("Illegal arguments : " + ip + "," + v4Mask);
        }
        StringBuilder subNet = new StringBuilder();
        String[] ipSegs = ip.split(DOT);
        String[] maskSegs = v4Mask.split(DOT);

        for (int i = 0; i < ipSegs.length; ++i) {
            String ipSeg = ipSegs[i];
            String maskSeg = maskSegs[i];
            int ipSegDigit = Integer.parseInt(ipSeg);
            int maskSegDigit = Integer.parseInt(maskSeg);
            int andResult = ipSegDigit & maskSegDigit;
            subNet.append(String.valueOf(andResult));
            if (i != ipSegs.length - 1) {
                subNet.append(".");
            }
        }
        return subNet.toString();
    }

    public static int getIpMaskBits(final String mask) {
        if (!isLegalIpV4(mask)) {
            return Integer.valueOf(mask);
        }
        String[] segs = mask.split(DOT);
        StringBuilder strV4 = new StringBuilder();

        for (final String seg : segs) {
            strV4.append(Integer.toBinaryString(Integer.valueOf(seg)));
        }

        return countMatches(strV4.toString(), "1");

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

    private static String join(Collection collection, String separator) {
        if (collection == null) {
            return null;
        }
        Iterator iterator = collection.iterator();

        if (!iterator.hasNext()) {
            return "";
        }
        Object first = iterator.next();
        if (!iterator.hasNext()) {
            return Objects.toString(first);
        }
        StringBuilder builder = new StringBuilder(256);
        if (first != null) {
            builder.append(first);
        }

        while (iterator.hasNext()) {
            if (separator != null) {
                builder.append(separator);
            }

            Object obj = iterator.next();
            if (obj != null) {
                builder.append(obj);
            }
        }

        return builder.toString();
    }


    private static String repeat(char ch, int repeat) {
        if (repeat <= 0) {
            return "";
        } else {
            char[] buf = new char[repeat];

            for (int i = repeat - 1; i >= 0; --i) {
                buf[i] = ch;
            }
            return new String(buf);
        }
    }
}

