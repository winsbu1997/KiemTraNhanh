import xml.dom.minidom

if __name__ == "__main__":
    doc = xml.dom.minidom.parse("report.xml")

    print(doc.nodeName)
    #Sprint("\n", doc._get_firstChild.values)    