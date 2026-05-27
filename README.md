# Cookie And Tracker Scanner

Use Playwright to visit a single website and record its tracking surface by logging network requests, scripts and cookie changes, then exporting the results as reports.

## Application Overview

This application normalizes the user-provided URL, launches a Chromium browser and navigates to the page using a wait condition and timeout. While the page loads, it hooks Playwright’s events and logs detailed metadata for each network request, resource type, headers, redirect chain, timestamps and more. It also classifies each event as being either first-party or third-party.

After navigation, the scanner captures the site’s cookie state and computes diffs showing which cookies were added, removed and/or changed. The application can also attempt to handle cookie-consent banners. Finally, it exports reports including JSON logs for requests stats and optionally human-friendly `report.md` and `report.html`.

## Basic Setup Instructions

Below are the required software programs and instructions for installing and using this application on a Linux machine.

### Programs Needed

- [Git](https://git-scm.com/downloads)

- [Python](https://www.python.org/downloads/)

### Steps For Use

1. Install the above programs

2. Open a terminal

3. Clone this repository: `git clone git@github.com:devbret/cookie-tracker-scanner.git`

4. Navigate to the repo's directory: `cd cookie-tracker-scanner`

5. Create a virtual environment: `python3 -m venv venv`

6. Activate your virtual environment: `source venv/bin/activate`

7. Install the needed dependencies: `pip install -r requirements.txt`

8. Run the program: `python3 app.py example.com`

9. Locate your output results in the `scans` directory

10. Exit the virtual environment: `deactivate`

## Other Considerations

This project repo is intended to demonstrate an ability to do the following:

- Scan a website with Playwright to measure its tracking surface

- Capture cookie behavior before and after page navigation, consent interactions, settling time and user actions

- Save scan screenshots, JSON summaries and Markdown reports for later analysis

If you have any questions or would like to collaborate, please reach out either on GitHub or via [my website](https://bretbernhoft.com/).
