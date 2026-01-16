# DURINN_GT id=a03_10_xml_parser track=sast set=core owasp=A03
import xml.etree.ElementTree as ET

def vuln(xml_text: str):
    return ET.fromstring(xml_text)
