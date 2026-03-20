# Cookie And Tracker Scanner

Uses Playwright to visit a single website and record its tracking surface by logging network requests, scripts and cookie changes, then exporting the results as reports and scan artifacts.

## Overview

This script normalizes the input URL, then launches a Chromium browser and navigates to the page using a configurable wait condition and timeout. While the page loads, it hooks Playwright’s events and logs detailed metadata for each network request and response-method, resource type, headers, redirect chain, frame URL, referer, status codes and timestamps. It also classifies each event as being either first-party or third-party by comparing each resource’s registrable domain to the scanned site’s domain.

After navigation, the scanner captures the site’s cookie state at several phases, enriches cookies with first/third-party classification and computes diffs showing which cookies were added, removed and/or changed between phases. It can also attempt to handle cookie-consent banners by clicking “reject” or “accept” and can perform scripted actions like scrolling, idling or clicking selectors to trigger additional tracking behavior. Finally, it exports a folder of artifacts including JSON logs for requests stats, a HAR file, Playwright trace zip, full-page screenshot, machine-readable `summary.json` and optionally human-friendly `report.md` and `report.html`.

## Set Up Instructions

Below are the required software programs and instructions for installing and using this application.

### Programs Needed

- [Git](https://git-scm.com/downloads)

- [Python](https://www.python.org/downloads/)

### Steps For Use

1. Install the above programs

2. Open a terminal

3. Clone this repository using `git` by running the following command: `git clone git@github.com:devbret/cookie-tracker-scanner.git`

4. Navigate to the repo's directory by running: `cd cookie-tracker-scanner`

5. Create a virtual environment with this command: `python3 -m venv venv`

6. Activate your virtual environment using: `source venv/bin/activate`

7. Install the needed dependencies for running the script: `pip install -r requirements.txt`

8. Run the program using a command such as: `python3 app.py example.com`

9. Locate your output results in the `scans` directory

10. To exit the virtual environment (venv), type this command in the terminal: `deactivate`

## Command Options And Flags

This program has a number of useful options available when running the application. Those individual features will be documented in upcoming `README.md` updates.

## Other Considerations

This project repo is intended to demonstrate an ability to do the following:

- Develop privacy tools for repeatable browswer-based auditing

- Output key findings from website scans in multiple file formats

If you have any questions or would like to collaborate, please reach out either on GitHub or via [my website](https://bretbernhoft.com/).
