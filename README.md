# WriteUp

## Flag 1

### Step 1: Initial Reconnaissance

I began by exploring the site `infosec.pclub.in`. Checking common entry points, I examined `robots.txt` and `sitemap.xml`, nothing juicy found there. There were 3 blogs live on the website.

- Observation: One of the blog revealed hacker's real name `Kalpit Lal Rama` which I used as a pivot point.
- Action: Visited google to search for the name. It lead me to a linkedIn profile, which further lead me to a [x.com] account and subsequently their [reddit account](https://www.reddit.com/user/Virtual-Copy-637/).

### Step 2: Reddit Investigation

The Reddit profile had some posts, 2 being latest and another 2 around 8 months old. One of the latest post had an image. Suspecting hidden data in the image, I analysed the image using tools like `steghide`, `binwalk`, `aperisolve` but found no hidden data. Even the posts didn't provide clear leads so I moved on to other avenues.
- The reddit posts lead me to a dead end for the time being.

### Step 3: Web Enumeration with `ffuf`
I performed directory enumeration using [`ffuf`](https://github.com/ffuf/ffuf) to uncove hidden paths on `infosec.pclub.in`. Despite extensive scanning, no useful directories or files were found.
 ```bash
 ffuf -u https://infosec.pclub.in/FUZZ -w directory-list-lowercase-2.3-medium.txt
 ```

### Step 4: Network Analysis
I analysed network traffic while interacting with the website, inspecting CDN-hosted javascript files (e.g. `jekyll-search.js`, `common.js`) for clues. No anomalies were found.

### Step 5: Blog Post Analysis and Grafana Discovery
Returning to the blog posts, in one of the post, I noticed a mention of a [Grafana](https://grafana.com/) instance running at `http://13.126.50.182:3000`. This was a promising lead.
- **Action**: Performed a `nmap` scan on the IP (`nmap -sV -sC 13.126.50.182`) to get services running on server. The scan revealed an OpenSSH 9.6 service on `port 22`.

![alt text](images/image.png)

- Observation: On searching google regarding OpenSSH version, I found a related CVE.

### Step 6: Exploring OpenSSH Vulnerability

Researching openssh 9.6p1 running with `Ubuntu 3ubuntu13.11`, I identified [`CVE-2024-6387`](https://nvd.nist.gov/vuln/detail/CVE-2024-6387) (**regreSSHion**), a critical vulnerability. I attempted exploiting it using a python script ([`CVE-2024-6387.py`](https://github.com/Karmakstylez/CVE-2024-6387)), via [Metasploit](https://www.metasploit.com/), but it, including more exploits scripts I tried, failed.
Further research included [Qualys' advisory](https://www.qualys.com/2024/07/01/cve-2024-6387/regresshion.txt) and a youtube analysis by `Low Level`, confirmed that no reliable PoC existed for this vulnerability, making it a dead end.
- Dead End: The OpenSSH exploit was not viable due to lack of a working PoC (due to the fact that on average it will take long time to exploit the race condition).

### Step 7: Grafana and Further Exploration

I explored the Grafana instance, was able to login using default credentials (`admin:admin`) for some time. I didn't find any useful information there, dashboards, data sources, alerts -- all were empty.
Explored grafana metrics (`http://13.126.50.182:3000/metrics`), which exposed Grafana internal metrics but contained no useful data.

### Step 8: Grafana version and LFI Exploitation

After someone changed password and doubt clarified about login issue, I had to repivot. Suspecting a vulnerability in Grafana, I checked `/login` page, which revealed Grafana `version 8.3.0`.
![alt text](images/image-1.png)

Searching online, I found a know [directory traversal and Local File inclusion (LFI) vulnerability](https://www.exploit-db.com/exploits/50581). Using this exploit I accessed servcer files.
- Key findings: I accessed `/etc/passwd`, though nothing juicy was found there. I also accessed `grafana.db` but even that didn't reveal any hidden information.

### Step 9: Hint release and Flag Discovery
After some days, a hint was released that pointed to some `temporary location` on server. After some tries, I got the flag file located at `/tmp/flag` on the server.
```bash
curl --path-as-is http://13.126.50.182:3000/public/plugins/prometheus/../../../../../../../../../../../tmp/flag
```
#### Flag 1: `PClub{Easy LFI}`


## Flag 2

### Step 10: New IPs and shell access

The first flag provided two new IPs: `13.235.21.137:4657` and `13.235.21.137:4729`. An Nmap service scan indicated a shell service on both ports. Using `netcat`, I connected and obtained a shell.
```bash
nc 13.235.21.137 4657
```;

### Step 11: Source code and Binary Analysis
In the shell, I found two files: a binary and its .c source code. The source code revealed that the binary opened `/root/flag`, set the user ID to a non-root user, and spawned a shell without closing the file descriptor for `/root/flag`.