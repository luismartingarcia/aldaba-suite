#!/bin/sh


echo "[+] Generating aldaba -h output"
if [ -f ../../aldaba ]
then
  ../../aldaba -h > aldaba-usage.txt
else
  echo "../../aldaba does not exist, using previous version of aldaba-usage.txt..."
fi


echo "[+] Generating aldabad -h output"
if [ -f ../../aldaba ]
then
  ../../aldabad -h > aldabad-usage.txt
else
  echo "../../aldabad does not exist, using previous version of aldabad-usage.txt..."
fi

echo "[+] Done!"
echo "[+] Generating aldaba man page from aldaba-man.xml"
#collateindex.pl -N -i idx -o genindex.sgm
xsltproc --stringparam doc.class man --xinclude --output ../../docs/aldaba.8 xsl/man.nroff.xsl aldabamanhtml.xml
echo "[+] Done!"


echo "[+] Done!"
echo "[+] Generating aldabad man page from aldabad-man.xml"
#collateindex.pl -N -i idx -o genindex.sgm
xsltproc --stringparam doc.class man --xinclude --output ../../docs/aldaba.8 xsl/man.nroff.xsl aldabadmanhtml.xml
echo "[+] Done!"


