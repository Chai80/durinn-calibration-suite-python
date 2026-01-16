# DURINN_GT id=a05_09_insecure_xml_parser track=sast set=core owasp=A05
import xml.etree.ElementTree as ET

def vuln(xml_text: str):
    return ET.fromstring(xml_text)
