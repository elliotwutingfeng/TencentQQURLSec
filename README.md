# TenCent QQ URLSec blocklist

![Python](https://img.shields.io/badge/Python-FFD43B?style=for-the-badge&logo=python&logoColor=blue)
![AIOHTTP](https://img.shields.io/badge/AIOHTTP-2C5BB4?style=for-the-badge&logo=aiohttp&logoColor=white)
![GitHub Actions](https://img.shields.io/badge/GitHub_Actions-2088FF?style=for-the-badge&logo=github-actions&logoColor=white)

[![GitHub license](https://img.shields.io/badge/LICENSE-BSD--3--CLAUSE-GREEN?style=for-the-badge)](LICENSE)
[![scraper](https://img.shields.io/github/workflow/status/elliotwutingfeng/TencentQQURLSec/scraper?label=SCRAPER&style=for-the-badge)](https://github.com/elliotwutingfeng/TencentQQURLSec/actions/workflows/scraper.yml)
<img src="https://img.shields.io/tokei/lines/github/elliotwutingfeng/TencentQQURLSec?label=Total%20Blocklist%20URLS&style=for-the-badge" alt="Total Blocklist URLs"/>

Tencent QQ has an undocumented publicly-accessible [real-time feed](https://urlsec.qq.com/cgi/risk/getList) of malicious URLs.

This repository extracts these URLs, at regular intervals, to a machine-readable `.txt` blocklist compatible with firewall applications like [Pi-hole](https://pi-hole.net) and [pfBlockerNG](https://docs.netgate.com/pfsense/en/latest/packages/pfblocker.html).

The URLs in this blocklist are compiled by **Tencent QQ**.

**Disclaimer:** _This project is not sponsored, endorsed, or otherwise affiliated with Tencent._

## Blocklist download

| File | Download |
|:-:|:-:|
| blocklist.txt | [:floppy_disk:](blocklist.txt?raw=true) |
| blocklist_ABP.txt | [:floppy_disk:](blocklist_ABP.txt?raw=true) |

## Threat categories

Each URL is numerically categorised by threat type with the parameter `evilclass`. The `evilclass` number for each URL is provided in the blocklist after the `#` symbol.

Translations are provided as-follows
```
# evilclass
{
	'1' : '社工欺诈', # Phishing
	'2' : '信息诈骗', # Scam
	'3' : '虚假广告', # False Advertising
	'4' : '恶意文件', # Malicious Files
	'5' : '博彩网站', # Gambling
	'6' : '色情内容', # Pornographic content
	'7' : '垃圾信息', # Spam
	'8' : '非法内容' # Illegal content (likely to contain politically censored websites)
}
```
Source: `https://github.com/flowerdown/tencent_url_safe_dump/blob/master/tencent_Dangerous_web.py`

More information (in chinese) on the parameter `evilclass` can be found at
`https://urlsec.qq.com/eviltype.html` and `https://urlsec.qq.com/wiki/#!md/SafeQueryHttp.md`



## Requirements

-   Python >= 3.10.5

## Setup instructions

`git clone` and `cd` into the project directory, then run the following

```bash
pip3 install -r requirements.txt
```

## Usage

```bash
python3 scraper.py
```

&nbsp;

<sup>These files are provided "AS IS", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose and noninfringement. In no event shall the authors or copyright holders be liable for any claim, damages or other liability, arising from, out of or in connection with the files or the use of the files.</sup>

<sub>Any and all trademarks are the property of their respective owners.</sub>
