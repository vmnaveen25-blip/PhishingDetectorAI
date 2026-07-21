from urllib.parse import urlparse
import ipaddress
import whois
import requests
from bs4 import BeautifulSoup
from datetime import datetime,timezone

def get_date(date_value):
    if isinstance(date_value, list):
        return date_value[0]
    return date_value


def extract_features(url):

    features = {}

    # Add http:// if missing
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed_url = urlparse(url)
    hostname = parsed_url.hostname
    if hostname is None:
        hostname = ""

    # -----------------------------------
    # Download Webpage
    # -----------------------------------
    try:
        response = requests.get(
            url,
            timeout=5,
            allow_redirects=True,
            headers={
                "User-Agent": "Mozilla/5.0"
            }
        )
        response.raise_for_status()
        html = response.text
        soup = BeautifulSoup(html, "lxml")

    except Exception:
        response = None
        soup = None

    # -----------------------------------
    # WHOIS Information
    # -----------------------------------
    if hostname:
        try:
            domain_info = whois.whois(hostname)
        except Exception:
            domain_info = None
    else:
        domain_info = None

    # -----------------------------------
    # 1. having_IP_Address
    # -----------------------------------
    try:
        ipaddress.ip_address(hostname)
        features["having_IP_Address"] = 1
    except Exception:
        features["having_IP_Address"] = -1

    # -----------------------------------
    # 2. URLURL_Length
    # -----------------------------------
    length = len(url)

    if length < 54:
        features["URLURL_Length"] = -1
    elif length <= 75:
        features["URLURL_Length"] = 0
    else:
        features["URLURL_Length"] = 1

    # -----------------------------------
    # 3. Shortining_Service
    # -----------------------------------
    shorteners = [
        "bit.ly", "tinyurl.com", "goo.gl",
        "t.co", "ow.ly", "is.gd",
        "buff.ly", "cutt.ly", "rebrand.ly"
    ]

    if any(service in hostname for service in shorteners):
        features["Shortining_Service"] = 1
    else:
        features["Shortining_Service"] = -1

    # -----------------------------------
    # 4. having_At_Symbol
    # -----------------------------------
    features["having_At_Symbol"] = 1 if "@" in url else -1

    # -----------------------------------
    # 5. double_slash_redirecting
    # -----------------------------------
    if url.rfind("//") > 7:
        features["double_slash_redirecting"] = 1
    else:
        features["double_slash_redirecting"] = -1

    # -----------------------------------
    # 6. Prefix_Suffix
    # -----------------------------------
    features["Prefix_Suffix"] = 1 if "-" in hostname else -1

    # -----------------------------------
    # 7. having_Sub_Domain
    # -----------------------------------
    dots = hostname.count(".")

    if dots == 1:
        features["having_Sub_Domain"] = -1
    elif dots == 2:
        features["having_Sub_Domain"] = 0
    else:
        features["having_Sub_Domain"] = 1

    # -----------------------------------
    # 8. SSLfinal_State
    # -----------------------------------
    features["SSLfinal_State"] = 1 if parsed_url.scheme == "https" else -1

    # -----------------------------------
    # 9. Domain_registeration_length
    # -----------------------------------
    if domain_info is not None:
        try:
            expiry = get_date(domain_info.expiration_date)
            if expiry:
                if expiry.tzinfo is None:
                    expiry = expiry.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                remaining = (expiry - now).days

                if remaining >= 365:
                    features["Domain_registeration_length"] = 1
                else:
                    features["Domain_registeration_length"] = -1
            else:
                features["Domain_registeration_length"] = -1
        except Exception:
            features["Domain_registeration_length"] = -1
    else:
        features["Domain_registeration_length"] = -1
    # -----------------------------------
    # 10. age_of_domain
    # -----------------------------------
    if domain_info is not None:
        try:
            creation = get_date(domain_info.creation_date)

            if creation:
                if creation.tzinfo is None: 
                    creation = creation.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                age = (now - creation).days

                if age >= 180:
                    features["age_of_domain"] = 1
                else:
                    features["age_of_domain"] = -1
            else:
                features["age_of_domain"] = -1

        except Exception:
            features["age_of_domain"] = -1
    else:
        features["age_of_domain"] = -1

    # -----------------------------------
    # 11. DNSRecord
    # -----------------------------------
    if domain_info is not None:
        try:
            if domain_info.name_servers:
                features["DNSRecord"] = 1
            else:
                features["DNSRecord"] = -1
        except Exception:
            features["DNSRecord"] = -1
    else:
        features["DNSRecord"] = -1

    # -----------------------------------
    # 12. Favicon
    # -----------------------------------
    if soup:

        favicon = soup.find(
        "link",
        rel=lambda x: x and "icon" in str(x).lower()
        )
        if favicon:
            href = favicon.get("href", "")

            if href.startswith("/") or hostname in href:
                features["Favicon"] = -1
            else:
                features["Favicon"] = 1
        else:
            features["Favicon"] = -1

    else:
        features["Favicon"] = -1
    # -----------------------------------
    # 13. port
    # -----------------------------------

    try:
        port = parsed_url.port

        if port is None:
            features["port"] = -1

        elif port in [80, 443]:
            features["port"] = -1

        else:
            features["port"] = 1
    except Exception:
        features["port"] = -1
    # -----------------------------------
    # 14. HTTPS_token
    # -----------------------------------
    if "https" in hostname.lower().replace("www.", ""):
        features["HTTPS_token"] = 1
    else:
        features["HTTPS_token"] = -1
    # -----------------------------------
    # 15. Request_URL
    # -----------------------------------
    if soup:

        total = 0
        external = 0

        tags = soup.find_all(["img", "audio", "embed", "iframe", "script"])

        for tag in tags:

            src = tag.get("src")

            if src:
                total += 1

                if hostname not in src and not src.startswith("/"):
                    external += 1

        if total == 0:
            features["Request_URL"] = -1

        else:
            percentage = (external / total) * 100

            if percentage < 22:
                features["Request_URL"] = -1
            elif percentage <= 61:
                features["Request_URL"] = 0
            else:
                features["Request_URL"] = 1

    else:
        features["Request_URL"] = -1
    # -----------------------------------
    # 16. URL_of_Anchor
    # -----------------------------------
    if soup:

        total = 0
        unsafe = 0

        anchors = soup.find_all("a")

        for anchor in anchors:

            href = anchor.get("href")

            if href:

                total += 1

                href = href.strip().lower()

                if (
                     href.startswith("#")
                or href.startswith("javascript")
                or href.startswith("mailto:")
                ):
                    unsafe += 1

                elif hostname not in href and not href.startswith("/"):
                    unsafe += 1

        if total == 0:
            features["URL_of_Anchor"] = -1

        else:

            percentage = (unsafe / total) * 100

            if percentage < 31:
                features["URL_of_Anchor"] = -1

            elif percentage <= 67:
                features["URL_of_Anchor"] = 0

            else:
                 features["URL_of_Anchor"] = 1

    else:
        features["URL_of_Anchor"] = -1
    # -----------------------------------
    # 17. Links_in_tags
    # -----------------------------------
    if soup:

        total = 0
        external = 0

        # ---------- LINK ----------
        for tag in soup.find_all("link"):

            href = tag.get("href")

            if href:
                total += 1

                if hostname not in href and not href.startswith("/"):
                    external += 1

        # ---------- SCRIPT ----------
        for tag in soup.find_all("script"):

            src = tag.get("src")

            if src:
                total += 1

                if hostname not in src and not src.startswith("/"):
                    external += 1

        # ---------- META ----------
        for tag in soup.find_all("meta"):

            content = tag.get("content")

            if content and "http" in content:

                total += 1

                if hostname not in content:
                    external += 1

        if total == 0:
            features["Links_in_tags"] = -1

        else:

            percentage = (external / total) * 100

            if percentage < 17:
                features["Links_in_tags"] = -1

            elif percentage <= 81:
                features["Links_in_tags"] = 0

            else:
                features["Links_in_tags"] = 1

    else:
        features["Links_in_tags"] = -1
    # -----------------------------------
    # 18. SFH
    # -----------------------------------
    if soup:

        forms = soup.find_all("form")

        if len(forms) == 0:

            features["SFH"] = -1

        else:

            suspicious = -1

            for form in forms:

                action = form.get("action")

                # Empty action
                if not action:
                    suspicious = 1
                    break

                action = action.strip().lower()

                # about:blank
                if action == "about:blank":
                    suspicious = 1
                    break

                # External domain
                if (
                    action.startswith("http")
                    and hostname not in action
                ):
                    suspicious = 0

            features["SFH"] = suspicious

    else:
        features["SFH"] = -1
    # -----------------------------------
    # 19. Submitting_to_email
    # -----------------------------------
    if soup:

        found = False

        # Check all forms
        for form in soup.find_all("form"):

            action = form.get("action", "").lower()

            if "mailto:" in action:
                found = True
                break

        # Check entire HTML
        if not found:

            if "mailto:" in html.lower() or "mail(" in html.lower():
                found = True

        if found:
            features["Submitting_to_email"] = 1
        else:
            features["Submitting_to_email"] = -1

    else:
        features["Submitting_to_email"] = -1
    # -----------------------------------
    # 20. Abnormal_URL
    # -----------------------------------
    if domain_info is not None:

        try:

            whois_domain = domain_info.domain_name

            if isinstance(whois_domain, list):
                whois_domain = whois_domain[0]

            if whois_domain:

                whois_domain = whois_domain.lower()
                host = hostname.lower()

                if whois_domain in host:
                    features["Abnormal_URL"] = -1
                else:
                    features["Abnormal_URL"] = 1

            else:
                features["Abnormal_URL"] = 1

        except Exception:
            features["Abnormal_URL"] = 1

    else:
        features["Abnormal_URL"] = 1
    # -----------------------------------
    # 21. Redirect
    # -----------------------------------
    try:
        if response:
            redirects = len(response.history)

            if redirects <= 1:
                features["Redirect"] = -1
            elif redirects <= 3:
                features["Redirect"] = 0
            else:
                features["Redirect"] = 1
        else:
            features["Redirect"] = -1

    except Exception:
        features["Redirect"] = -1
    # -----------------------------------
    # 22. on_mouseover
    # -----------------------------------
    if soup:
        try:
            mouseover = False
            for tag in soup.find_all(True):
                if tag.has_attr("onmouseover"):
                    mouseover = True
                    break

            features["on_mouseover"] = 1 if mouseover else -1
        except Exception:
            features["on_mouseover"] = -1
    else:
        features["on_mouseover"] = -1


    # -----------------------------------
    # 23. RightClick
    # -----------------------------------
    if soup:
        try:
            html = str(soup).lower()

            if "event.button==2" in html or "contextmenu" in html:
                features["RightClick"] = 1
            else:
                features["RightClick"] = -1

        except Exception:
            features["RightClick"] = -1
    else:
        features["RightClick"] = -1


    # -----------------------------------
    # 24. popUpWidnow
    # -----------------------------------
    if soup:
        try:
            html = str(soup).lower()

            if (
                "alert(" in html
                or "prompt(" in html
                or "confirm(" in html
                or "window.open(" in html
            ):
                features["popUpWidnow"] = 1
            else:
                features["popUpWidnow"] = -1

        except Exception:
            features["popUpWidnow"] = -1
    else:
        features["popUpWidnow"] = -1
    # -----------------------------------
    # 25. Iframe
    # -----------------------------------
    if soup:
        try:
            iframe = soup.find("iframe")

            if iframe:
                if iframe.get("width") == "0" or iframe.get("height") == "0":
                    features["Iframe"] = 1
                else:
                    features["Iframe"] = 0
            else:
                features["Iframe"] = -1

        except Exception:
            features["Iframe"] = -1

    else:
        features["Iframe"] = -1
    # -----------------------------------
    # 26. web_traffic
    # -----------------------------------
    # Placeholder
    # Needs SimilarWeb / Tranco / Cisco Umbrella API
    features["web_traffic"] = 0


    # -----------------------------------
    # 27. Page_Rank
    # -----------------------------------
    # Placeholder
    # Google PageRank API no longer exists
    features["Page_Rank"] = 0


    # -----------------------------------
    # 28. Google_Index
    # -----------------------------------
    # Placeholder
    # Requires Google Search API or Custom Search API
    features["Google_Index"] = 0


    # -----------------------------------
    # 29. Links_pointing_to_page
    # -----------------------------------
    if soup:
        try:
            backlinks = len(soup.find_all("a"))

            if backlinks == 0:
                features["Links_pointing_to_page"] = 1
            elif backlinks <= 2:
                features["Links_pointing_to_page"] = 0
            else:
                features["Links_pointing_to_page"] = -1

        except Exception:
            features["Links_pointing_to_page"] = -1
    else:
        features["Links_pointing_to_page"] = -1


    # -----------------------------------
    # 30. Statistical_report
    # -----------------------------------
    suspicious_domains = [
        "at.ua",
        "usa.cc",
        "baltazarpresentes.com.br",
        "ow.ly",
        "bit.ly",
        "tinyurl.com"
    ]

    suspicious_ips = [
        "146.112.61.108",
        "54.83.43.69",
        "192.185.217.116"
    ]

    try:
        ip = requests.get(
            f"https://dns.google/resolve?name={hostname}&type=A",
            timeout=3
        ).json()

        resolved_ip = ""

        if "Answer" in ip:
            resolved_ip = ip["Answer"][0]["data"]

        if hostname in suspicious_domains or resolved_ip in suspicious_ips:
            features["Statistical_report"] = 1
        else:
            features["Statistical_report"] = -1

    except Exception:
        features["Statistical_report"] = -1

    return features