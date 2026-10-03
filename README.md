# XrayR

[![](https://img.shields.io/badge/TgChat-@XrayR讨论-blue.svg)](https://t.me/XrayR_project)
[![](https://img.shields.io/badge/Channel-@XrayR通知-blue.svg)](https://t.me/XrayR_channel)
![](https://img.shields.io/github/stars/Mtoly/XrayRP)
![](https://img.shields.io/github/forks/Mtoly/XrayRP)
![](https://github.com/Mtoly/XrayRP/actions/workflows/release.yml/badge.svg)
![](https://github.com/Mtoly/XrayRP/actions/workflows/docker.yml/badge.svg)
[![Github All Releases](https://img.shields.io/github/downloads/Mtoly/XrayRP/total.svg)]()


[English](https://github.com/Mtoly/XrayRP/blob/master/README-en.md)|[Iranian](https://github.com/Mtoly/XrayRP/blob/master/README_Fa.md)|[Vietnamese](https://github.com/Mtoly/XrayRP/blob/master/README-vi.md)

A Xray backend framework that can easily support many panels.

一个基于Xray的后端框架，支持V2ay,Trojan,Shadowsocks协议，极易扩展，支持多面板对接。

如果您喜欢本项目，可以右上角点个star+watch，持续关注本项目的进展。

使用教程：[详细使用教程](https://xrayr-project.github.io/XrayR-doc/)


## 免责声明

本项目只是本人个人学习开发并维护，本人不保证任何可用性，也不对使用本软件造成的任何后果负责。

## 特点

* 永久开源且免费。
* 支持V2ray，Trojan， Shadowsocks多种协议。
* 支持Vless和XTLS等新特性。
* 支持单实例对接多面板、多节点，无需重复启动。
* 支持限制在线IP
* 支持节点端口级别、用户级别限速。
* 配置简单明了。
* 修改配置自动重启实例。
* 方便编译和升级，可以快速更新核心版本， 支持Xray-core新特性。

## 功能介绍

### XHTTP + VLESS Encryption + Vision

在对应节点的 `ControllerConfig` 下设置 `VlessDecryption`，值为 `xray vlessenc`
生成的服务端 `decryption` 字符串。省略、空字符串或 `"none"` 保持原来的无协议层加密行为。
启用 VLESS Encryption 后，XHTTP 等非 TCP 传输也可以保留 Vision：

```yaml
Nodes:
  - PanelType: "SSPanel"
    ApiConfig:
      # 保留现有 ApiHost、ApiKey、NodeID 等设置
      NodeType: V2ray
      EnableVless: true
      VlessFlow: "xtls-rprx-vision"
    ControllerConfig:
      # 替换成配套的服务端值；私钥不要放进订阅
      VlessDecryption: "mlkem768x25519plus.native.600s.<PRIVATE_KEY>"
      EnableFallback: false
      # 保留现有 ListenIP、REALITYConfigs 等设置
```

面板仍需配置 XHTTP 传输，客户端需要配套的 `encryption` 字符串及
`flow: xtls-rprx-vision`，并使用支持此组合的 Xray 核心。
`VlessDecryption` 不替代 REALITY 密钥，也不会自动修改面板订阅。
VLESS Encryption 不能与 VLESS fallback 同时启用；非法参数由 Xray 核心拒绝。

参考：[VLESS 入站配置](https://xtls.github.io/config/inbounds/vless.html)、
[VLESS 出站配置](https://xtls.github.io/config/outbounds/vless.html)。

| 功能        | v2ray | trojan | shadowsocks |
|-----------|-------|--------|-------------|
| 获取节点信息    | √     | √      | √           |
| 获取用户信息    | √     | √      | √           |
| 用户流量统计    | √     | √      | √           |
| 服务器信息上报   | √     | √      | √           |
| 自动申请tls证书 | √     | √      | √           |
| 自动续签tls证书 | √     | √      | √           |
| 在线人数统计    | √     | √      | √           |
| 在线用户限制    | √     | √      | √           |
| 审计规则      | √     | √      | √           |
| 节点端口限速    | √     | √      | √           |
| 按照用户限速    | √     | √      | √           |
| 自定义DNS    | √     | √      | √           |

## 支持前端

| 前端                                                     | v2ray | trojan | shadowsocks             |
|--------------------------------------------------------|-------|--------|-------------------------|
| sspanel-uim                                            | √     | √      | √ (单端口多用户和V2ray-Plugin) |
| v2board                                                | √     | √      | √                       |
| [PMPanel](https://github.com/ByteInternetHK/PMPanel)   | √     | √      | √                       |
| [ProxyPanel](https://github.com/ProxyPanel/ProxyPanel) | √     | √      | √                       |
| [WHMCS (V2RaySocks)](https://v2raysocks.doxtex.com/)   | √     | √      | √                       |
| [GoV2Panel](https://github.com/pingProMax/gov2panel)   | √     | √      | √                       |
| [BunPanel](https://github.com/pennyMorant/bunpanel-release)   | √     | √      | √                       |

## 软件安装

### 一键安装

```
wget -N https://raw.githubusercontent.com/Mtoly/XrayRP-release/master/install.sh && bash install.sh
```

### 使用Docker部署软件

[Docker部署教程](https://xrayr-project.github.io/XrayR-doc/xrayr-xia-zai-he-an-zhuang/install/docker)

### 手动安装

[手动安装教程](https://xrayr-project.github.io/XrayR-doc/xrayr-xia-zai-he-an-zhuang/install/manual)

## 配置文件及详细使用教程

[详细使用教程](https://xrayr-project.github.io/XrayR-doc/)

## Thanks

* [Project X](https://github.com/XTLS/)
* [V2Fly](https://github.com/v2fly)
* [VNet-V2ray](https://github.com/ProxyPanel/VNet-V2ray)
* [Air-Universe](https://github.com/crossfw/Air-Universe)

## Licence

[Mozilla Public License Version 2.0](https://github.com/Mtoly/XrayRP/blob/master/LICENSE)

## Telgram

[XrayR后端讨论](https://t.me/XrayR_project)

[XrayR通知](https://t.me/XrayR_channel)

## Stargazers over time

[![Stargazers over time](https://starchart.cc/Mtoly/XrayRP.svg)](https://starchart.cc/Mtoly/XrayRP)


