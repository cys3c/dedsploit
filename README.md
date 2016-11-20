# dedsploit
Framework for attacking network protocols and network exploitation.

__Official Website:__ http://dedsploit.github.io

![Logo](/src/logo.png)

## Written for DefHacks Fall 2016 Hackathon. [More information here](https://def-hacks-fall-2016.devpost.com/)

### I. Introduction

> I don't look back anymore. I don't regret.
> I look forward

- Aiden Pearce

Yes, Watch Dogs has heavily influenced us when writing this framework. This entire project brought upon a lot of the ideals from the Watch Dogs franchise, and even actual hacking culture, to life. This framework aims to exploit and attack some common every-day vulnerabilities, whether it is a misconfiguration of a SSH server, or even the utilization of `apache2` as a web server, which could be subjected to malicious __Slowloris__ DoS attacks.

The framework comprises of several modules, and within each module will be attack vectors.

    main
    |
    +--SSH
    |    +--
    |       |- bruteforce - bruteforce vulnerable SSH server
    |
    +--SMTP
    |     +--
    |        | - bruteforce - bruteforce SMTP address (aka email)
    |        |
    |        | - smsbomb - utilizes smtp-to-email gateway to spam SMS messages
    |
    +--HTTP
    |      +--
    |         | - arpspoof - MITM where user fakes ARP messages on LAN, intercepting packets from host
    |         |
    |         | - slowloris - Layer-7 DoS attack using slow headers and malformed GET requests to a vulnerable web server
    |
    +--Recon
    |       +--
    |          | - pscan - port scan with Nmap
    |          |
    |          | - hosts - scan for active hosts
    |
    +------

### II. Installation & Usage

### III. To-Do List

### IV. 
