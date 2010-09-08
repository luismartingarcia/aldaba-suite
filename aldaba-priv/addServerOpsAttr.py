methname = raw_input("Method name: ")
attrname = raw_input("Attr name: ")
attrtype = raw_input("Attr type: ")


o = open("server.txt","a") 
for line in open("TemplateClientOps.txt"):
   line = line.replace("ATTRNAME",attrname)
   line = line.replace("METHNAME",methname)
   line = line.replace("TYPE",attrtype)
   o.write(line) 
o.close()
