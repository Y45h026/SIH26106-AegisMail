import requests


def lookup_ip(ip):
    url = f"http://ip-api.com/json/{ip}"
    response = requests.get(url, timeout=5)
    data = response.json()

    if data.get("status") != "success":
        print("Error:", data.get("message", "Unknown error"))
        return

    print("IP:", ip)
    print("City:", data.get("city"))
    print("Country:", data.get("country"))
    print("Latitude:", data.get("lat"))
    print("Longitude:", data.get("lon"))
    print("ISP:", data.get("isp"))


if __name__ == "__main__":
    lookup_ip("8.8.8.8")