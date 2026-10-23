# Aged inventory reports

Published copy of the Silver Fox aged-inventory site: pick a dealership, see how long its new
vehicles have been on the lot, from the latest inventory scrape.

**This repository is generated. Don't edit it here.** It is rebuilt and replaced (one commit,
force-pushed) after each weekday-morning scrape. The source lives in Barrett's knowledge vault
under `output/vehicle-scraper/aged-inventory/`.

The dealer data in `data/` is encrypted (AES-256-GCM, key derived from the team password with
PBKDF2-SHA256). Without the password the files are unreadable; the page itself holds no data.
