# Cookie And Tracker Scanner

Uses Playwright to visit a single website and record its tracking surface by logging network requests, scripts and cookie changes, then exporting the results as reports and scan artifacts.

## Overview

This script normalizes the input URL, then launches a Chromium browser and navigates to the page using a configurable wait condition and timeout. While the page loads, it hooks Playwright’s events and logs detailed metadata for each network request and response-method, resource type, headers, redirect chain, frame URL, referer, status codes and timestamps. It also classifies each event as being either first-party or third-party by comparing each resource’s registrable domain to the scanned site’s domain.

After navigation, the scanner captures the site’s cookie state at several phases, enriches cookies with first/third-party classification and computes diffs showing which cookies were added, removed and/or changed between phases. It can also attempt to handle cookie-consent banners by clicking “reject” or “accept” and can perform scripted actions like scrolling, idling or clicking selectors to trigger additional tracking behavior. Finally, it exports a folder of artifacts including JSON logs for requests stats, a HAR file, Playwright trace zip, full-page screenshot, machine-readable `summary.json` and optionally human-friendly `report.md` and `report.html`.
