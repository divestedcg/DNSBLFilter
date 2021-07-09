DNSBLFilter
===========

Overview
--------
A shoddy program used to identify domains by keyword matching.

Quick Start
-----------
- Clone the repo
- wget https://divested.dev/Domains.txt.zst
- unzstd Domains.txt.zst
- sh build.sh
- mkdir Generated
- ./analyze

Legal
-----
- Domains.txt is 188 million domain names, in theory it cannot be copyrighted.
- Companies-*.txt are lists of thousands of companies, it too in theory cannot be copyrighted.

Credits
-------
- Domains.txt
    - DNS Census 2013
    - plus many other sources
- Companies-Better.txt
    - Better.fyi
    - CC BY-SA 4.0
    - https://source.small-tech.org/better/content/-/tree/master/trackers
- Companies-Martech.txt
    - Martech 5000 by Scott Brinker of chiefmartec.com
    - "Feel free to cut-and-paste this data and use it as a starting point for your own research."
    - https://web.archive.org/web/20170511212827/https://chiefmartec.com/2017/05/marketing-techniology-landscape-supergraphic-2017/
- Companies-Quids.txt
    - @Quidsup NoTrack List
    - GPL-3.0
    - https://gitlab.com/quidsup/notrack-blocklists

Donate
-------
- https://divested.dev/donate
