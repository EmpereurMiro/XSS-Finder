import requests
from pystyle import Write, Colors, Colorate, Center
import os
from pprint import pprint
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin

banner = """

        ▀████    ▐████▀    ▄████████    ▄████████         ▄████████  ▄█  ███▄▄▄▄   ████████▄     ▄████████    ▄████████ 
          ███▌   ████▀    ███    ███   ███    ███        ███    ███ ███  ███▀▀▀██▄ ███   ▀███   ███    ███   ███    ███ 
           ███  ▐███      ███    █▀    ███    █▀         ███    █▀  ███▌ ███   ███ ███    ███   ███    █▀    ███    ███ 
           ▀███▄███▀      ███          ███              ▄███▄▄▄     ███▌ ███   ███ ███    ███  ▄███▄▄▄      ▄███▄▄▄▄██▀ 
           ████▀██▄     ▀███████████ ▀███████████      ▀▀███▀▀▀     ███▌ ███   ███ ███    ███ ▀▀███▀▀▀     ▀▀███▀▀▀▀▀   
          ▐███  ▀███             ███          ███        ███        ███  ███   ███ ███    ███   ███    █▄  ▀███████████ 
         ▄███     ███▄     ▄█    ███    ▄█    ███        ███        ███  ███   ███ ███   ▄███   ███    ███   ███    ███ 
        ████       ███▄  ▄████████▀   ▄████████▀         ███        █▀    ▀█   █▀  ████████▀    ██████████   ███    ███ 
                                                                                                             ███    ███ 





"""

os.system("mode 130,40")
os.system("title XSS Finder - Waiting site ... - @EmpereurMrio")
os.system("cls")

print(Center.XCenter(Colorate.Vertical(Colors.black_to_red, banner, 1)))

url = Write.Input("[?] What is the targeted url >>> ", Colors.red_to_purple, interval=0)
os.system("title XSS Finder - [!] Targeted Site : " + url + " - @EmpereurMrio")
print(" \n \n ")

def get_all_forms(url):
  """Given a `url`, it returns all forms from the HTML content"""
  soup = bs(requests.get(url).content, "html.parser")
  return soup.find_all("form")


def get_form_details(form):
  """
    This function extracts all possible useful information about an HTML `form`
    """
  details = {}
  # get the form action (target url)
  action = form.attrs.get("action", "").lower()
  # get the form method (POST, GET, etc.)
  method = form.attrs.get("method", "get").lower()
  # get all the input details such as type and name
  inputs = []
  for input_tag in form.find_all("input"):
    input_type = input_tag.attrs.get("type", "text")
    input_name = input_tag.attrs.get("name")
    inputs.append({"type": input_type, "name": input_name})
  # put everything to the resulting dictionary
  details["action"] = action
  details["method"] = method
  details["inputs"] = inputs
  return details


def submit_form(form_details, url, value):
  """
    Submits a form given in `form_details`
    Params:
        form_details (list): a dictionary that contain form information
        url (str): the original URL that contain that form
        value (str): this will be replaced to all text and search inputs
    Returns the HTTP Response after form submission
    """
  # construct the full URL (if the url provided in action is relative)
  target_url = urljoin(url, form_details["action"])
  # get the inputs
  inputs = form_details["inputs"]
  data = {}
  for input in inputs:
    # replace all text and search values with `value`
    if input["type"] == "text" or input["type"] == "search":
      input["value"] = value
    input_name = input.get("name")
    input_value = input.get("value")
    if input_name and input_value:
      # if input name and value are not None,
      # then add them to the data of form submission
      data[input_name] = input_value

  print(Colorate.Horizontal(Colors.white_to_blue, f"[+] Submitting malicious payload to {target_url}", 1))
  print(Colorate.Horizontal(Colors.white_to_blue, f"[+] Data: {data}", 1))
  if form_details["method"] == "post":
    return requests.post(target_url, data=data)
  else:
    # GET request
    return requests.get(target_url, params=data)


def scan_xss(url):
  forms = get_all_forms(url)
  print(Colorate.Horizontal(Colors.white_to_blue, f"[+] Detected {len(forms)} forms on {url}.", 1))
  js_script = "<Script>alert('hi')</scripT>"
  is_vulnerable = False
  for form in forms:
    form_details = get_form_details(form)
    content = submit_form(form_details, url, js_script).content.decode()
    if js_script in content:
      print(Colorate.Horizontal(Colors.white_to_blue, f"[+] XSS Detected on {url}", 1))
      print(Colorate.Horizontal(Colors.white_to_blue, f"[*] Form details:", 1))
      pprint(form_details)
      is_vulnerable = True
  if is_vulnerable is False:
    print("")
    print(Colorate.Horizontal(Colors.red_to_white, "[!] No XSS Vulnerabilities", 1))
    print("")
  else:
    print("")
    print(Colorate.Horizontal(Colors.white_to_green, "[!] XSS Vulnerabilities Detected", 1))
    print("")
  is_vulnerable = ""
  return is_vulnerable

if __name__ == "__main__":
  print(scan_xss(url))
  os.system("pause>nul")
