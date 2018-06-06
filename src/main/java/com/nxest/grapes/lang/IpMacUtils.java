package com.nxest.grapes.lang;

import java.util.regex.Pattern;

/**
 * A collection of InetAddresses utilities.
 *
 * IP地址，一共分成了5类，范围分别如下：
 * A类IP：从0.0.0.0 – 127.255.255.255，共有16777216个IP
 * B类IP：从128.0.0.0 – 191.255.255.255，共有65536个IP
 * C类IP：从192.0.0.0 – 223.255.255.255，共有256个IP
 * D类IP：从224.0.0.0 – 239.255.255.255
 * E类IP：从2240.0.0.0 – 255.255.255.255
 *
 * @author l10178
 */
public class IpMacUtils {

    private static final String IPV4_REGEX = "^(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)(\\.(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)){3}$";
    private static final Pattern IPV4_PATTERN = Pattern.compile(IPV4_REGEX);

    private static final String IPV6_STD_REGEX = "^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$";
    private static final Pattern IPV6_STD_PATTERN = Pattern.compile(IPV6_STD_REGEX);

    private static final String IPV6_HEX_COMPRESSED_REGEX = "^((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?)::((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?)$";
    private static final Pattern IPV6_HEX_COMPRESSED_PATTERN = Pattern.compile(IPV6_HEX_COMPRESSED_REGEX);

    public static final long INVALID_IPV4 = 0L;

    private IpMacUtils() {
    }

    public static boolean isIpV4Address(final String ip) {
        return IPV4_PATTERN.matcher(ip).matches();
    }

    public static boolean isIpV6StandAddress(final String ip) {
        return IPV6_STD_PATTERN.matcher(ip).matches();
    }

    public static boolean isIpV6HexCompressedAddress(final String ip) {
        return IPV6_HEX_COMPRESSED_PATTERN.matcher(ip).matches();
    }

    public static boolean isIpV6Address(final String ip) {
        return isIpV6StandAddress(ip) || isIpV6HexCompressedAddress(ip);
    }

    public static String longToIpV4(final long longIp) {
        return ((longIp >> 24) & 0xFF) +
            "." + ((longIp >> 16) & 0xFF) +
            "." + ((longIp >> 8) & 0xFF) +
            "." + (longIp & 0xFF);
    }

    public static long ipV4ToLong(final String ip) {
        if (!isIpV4Address(ip)) {
            return INVALID_IPV4;
        }
        String[] octets = ip.split("\\.");
        return (Long.parseLong(octets[0]) << 24) + (Integer.parseInt(octets[1]) << 16)
            + (Integer.parseInt(octets[2]) << 8) + Integer.parseInt(octets[3]);
    }
}
