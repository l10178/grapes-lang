package com.nxest.grapes.lang;

/**
 * IP classes, A B C D E
 */
public enum IpClassEnum {

    /**
     * Class A IP, 0.0.0.0 – 127.255.255.255
     */
    A("A", "0.0.0.0-127.255.255.255"),
    /**
     * Class B IP, 128.0.0.0 – 191.255.255.255
     */
    B("B", "128.0.0.0–191.255.255.255"),
    /**
     * Class C IP, 192.0.0.0 – 223.255.255.255
     */
    C("C", "192.0.0.0–223.255.255.255"),
    /**
     * Class D IP, 224.0.0.0 – 239.255.255.255
     */
    D("D", "224.0.0.0–239.255.255.255"),
    /**
     * Class E IP, 240.0.0.0 – 255.255.255.255
     */
    E("E", "240.0.0.0–255.255.255.255");

    private String name;
    private String range;

    IpClassEnum(String name, String range) {
        this.name = name;
        this.range = range;
    }

    public String getName() {
        return name;
    }

    public String getRange() {
        return range;
    }

    @Override
    public String toString() {
        return "IpClassEnum{" +
            "name='" + name + '\'' +
            ", range='" + range + '\'' +
            '}';
    }
}
