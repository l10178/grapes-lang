grapes-lang
----------
 [![Build Status](https://travis-ci.org/l10178/grapes-lang.svg?branch=master)](https://travis-ci.org/l10178/grapes-lang)
 [![Maven Central]( https://maven-badges.herokuapp.com/maven-central/com.nxest.grapes/grapes-lang/badge.svg)]( https://maven-badges.herokuapp.com/maven-central/com.nxest.grapes/grapes-lang/)
 [![License](https://img.shields.io/github/license/mashape/apistatus.svg)](https://opensource.org/licenses/MIT)

A collection of IP and MAC utilities. For example, convert an IP string address to an unique long value and viceversa.


Download
----------
Download the [JARs](https://search.maven.org/search?q=a:grapes-lang). Or for Maven, add to your pom.xml:

```xml
<dependency>
  <groupId>com.nxest.grapes</groupId>
  <artifactId>grapes-lang</artifactId>
  <version>0.0.4</version>
</dependency>
```

Examples
----------

1. Convert an IP string address to an unique long value and viceversa.
```java
@Test
void ipV4ToLong() {
    assertEquals(3232235521L, IpMacUtils.ipV4ToLong("192.168.0.1"));
}
```

2. If legal IpV4 or IpV6.

```java
@Test
void isLegalIpV4() {
    assertTrue(IpMacUtils.isLegalIpV4("192.168.0.1"));
    assertFalse(IpMacUtils.isLegalIpV4("a.b.d.e"));
    assertFalse(IpMacUtils.isLegalIpV4("192.0."));
}
@Test
void isLegalIpV6() {
    assertTrue(IpMacUtils.isLegalIpV6("2001:0000:3238:DFE1:0063:0000:0000:FEFB"));
    assertFalse(IpMacUtils.isLegalIpV6("2001:0:3238:DFE1:63:::FEFB"));
}
```


License
----------
Licensed under [MIT][]. Copyright (c) 2018 [l10178][]

[MIT]: https://opensource.org/licenses/MIT
[l10178]: http://nxest.com/
