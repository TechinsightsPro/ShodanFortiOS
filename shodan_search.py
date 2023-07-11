# FIND RECENTLY PATCHED FORTIOS DEVICES IN A PARTICULAR REGION (CVE-2023-27997)
from datetime import date, timedelta
from shodan import Shodan

api = Shodan('<YOUR API KEY>')

def daterange(start_date, end_date):
    for n in range(int((end_date - start_date).days)+1):
        yield start_date + timedelta(n)

start_date = date(2023, 5, 1)
end_date = date(2023, 6, 30)
for single_date in daterange(start_date, end_date):
    fortigates = api.count('"Server: xxxxxxxx-xxxxx" country:SI,HR,BA,RS,ME,MK,AL,XK http.html:"top.location=/remote/login" "'+single_date.strftime("Last-Modified: %a, %d %b %Y")+'"')
    print(fortigates['total'])
