# meshbot-udp

A bot parsing, crafting and sending Meshtastic packets sent via udp multicast



## extra tricks

Cross-build for Asus RT-AX59U with arm64 cpu running OpenWrt

```
cross build --release --target aarch64-unknown-linux-musl
```

Cross-build for Asus RT-AX53U with mips cpu running OpenWrt

```
cross +nightly build -Z build-std --release --target mipsel-unknown-linux-musl
```
