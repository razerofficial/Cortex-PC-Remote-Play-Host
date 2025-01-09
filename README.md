# Overview

## About

Razer PC Remote Play Host is a self-hosted game streaming solution developed as a sub-module of [Razer Cortex](https://www.razer.com/cortex). It is based on [Sunshine](https://github.com/LizardByte/Sunshine) and supports the Remote Play Client across platforms, including [PC](https://www.razer.com/cortex), [IOS](https://github.com/razerofficial/Razer-PC-Remote-Play-ios), [Android](https://github.com/razerofficial/Razer-PC-Remote-Play-android), and Handheld Consoles, as well as Moonlight. Key features include:

- **Low latency and cloud gaming server capabilities:** Supports hardware encoding with AMD, Intel, and NVIDIA GPUs.
- **Virtual display and speaker modes:** Provides enhanced compatibility for diverse use cases.
- **Synchronized game library:** Fully integrated with Razer Cortex.
- **Fast and seamless connection:** Optimized for Razer Accounts.
- **Open-source:** Distributed under the [GPL-3.0 license](https://www.razer.com/cortex).

## System Requirements

> **Warning**: These specifications are subject to change. Please do not purchase hardware solely based on this information.

### Minimum Requirements

| Component | Requirement |
|-----------|-------------|
| **GPU**   | - **AMD:** VCE 1.0 or higher ([OBS AMD Hardware Support](https://github.com/obsproject/obs-amd-encoder/wiki/Hardware-Support))<br>- **Intel:** Linux: VAAPI-compatible ([VAAPI Support](https://www.intel.com/content/www/us/en/developer/articles/technical/linuxmedia-vaapi.html)), Windows: Skylake or newer with QuickSync encoding support<br>- **NVIDIA:** NVENC-enabled cards ([NVENC Support Matrix](https://developer.NVIDIA.com/video-encode-and-decode-gpu-support-matrix-new)) |
| **CPU**   | - **AMD:** Ryzen 3 or higher<br>- **Intel:** Core i3 or higher |
| **RAM**   | 4GB or more |
| **OS**    | Windows 11  |
| **Network** | Host: 5GHz, 802.11ac<br>Client: 5GHz, 802.11ac |

### Recommendations for 4K Streaming

| Component | Requirement |
|-----------|-------------|
| **GPU**   | - **AMD:** Video Coding Engine 3.1 or higher<br>- **Intel:** Skylake or newer with QuickSync encoding support<br>- **NVIDIA:** GeForce GTX 1080 or higher |
| **CPU**   | - **AMD:** Ryzen 5 or higher<br>- **Intel:** Core i5 or higher |
| **Network** | Host: CAT5e Ethernet or better<br>Client: CAT5e Ethernet or better |

### Recommendations for HDR Streaming

| Component | Requirement |
|-----------|-------------|
| **GPU**   | - **AMD:** Video Coding Engine 3.4 or higher<br>- **Intel:** HD Graphics 730 or higher<br>- **NVIDIA:** Pascal-based GPU (GTX 10-series) or higher |
| **CPU**   | - **AMD:** Ryzen 5 or higher<br>- **Intel:** Core i5 or higher |
| **Network** | Host: CAT5e Ethernet or better<br>Client: CAT5e Ethernet or better |


## Usage

Refer to LizardByte's documentation hosted on Read the How to [build](https://docs.lizardbyte.dev/projects/sunshine/en/latest/building/build.html). All features are only guaranteed to work when integrated with [Razer Cortex](https://www.razer.com/cortex). 

Therefore, you must first install Razer Cortex and then install Razer PC Remote Host within Razer Cortex.

Then, use the files you compiled to overwrite files that in this directory.
>%localappdata%\Razer\Razer Cortex\RemotePlay\Host

And, Click **START HOSTING** button in **REMOTE PLAY** - **RUN AS HOST**.

## Support

For additional information, refer to the [Razer Cortex FAQ](https://mysupport.razer.com/app/answers/detail/a_id/6104/~/razer-cortex-10-support-%26-faqs).

