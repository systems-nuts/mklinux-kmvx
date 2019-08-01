# kMVX: Detecting Kernel Information Leaks with Multi-variant Execution

This work will be presented at [ASPLOS 19](https://asplos-conference.org). We will publish the source code at the time of the conference.
In the meantime, you can grab the paper titled [kMVX: Detecting Kernel Information Leaks with Multi-variant Execution](https://osterlund.xyz/static/asplos19-kmvx.pdf).

## Abstract
Kernel information leak vulnerabilities are a major security threat to production systems. Attackers can exploit them to leak confidential information such as cryptographic keys or kernel pointers. Despite efforts by kernel developers and researchers, existing defenses for kernels such as Linux are limited in scope or incur a prohibitive performance overhead.
In this paper, we present kMVX, a comprehensive defense against information leak vulnerabilities in the kernel by running multiple diversified kernel variants simultaneously on the same machine. By constructing these variants in a careful manner, we can ensure they only show divergences when an attacker tries to exploit bugs present in the kernel. By detecting these divergences we can prevent kernel information leaks. Our kMVX design is inspired by multi-variant execution (MVX). Traditional MVX designs cannot be applied to kernels because of their assumptions on the run-time environment. kMVX, on the other hand, can be applied even to commodity kernels. We show our Linux-based prototype provides powerful protection against information leaks at acceptable performance overhead (20–50% in the worst case for popular server applications).
