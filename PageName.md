# Dependencies #

Pyew depends on many 3rd party components, various of them distributed with the pyew's source code. The dependencies are:

  * [Python](http://www.python.org), obviously.
  * [diStorm64](http://ragestorm.net/distorm/) (and pydistorm), for disassembly of x86. Distributed with the package.
  * [PEFile and PEUtils](http://code.google.com/p/pefile/), support for PE file format. Distributed with the package.
  * [OleFileIO\_PL](http://www.decalage.info/python/olefileio), support for the OLE2 container format. Distributed with the package.
  * [PDFID](http://blog.didierstevens.com/programs/pdf-tools/#pdfid), support for the PDF format. Distributed with the package.
  * [Libemu](http://libemu.carnivore.it/) and the python extension. Not distributed.
  * [Python Imaging Library (PIL)](http://www.pythonware.com/products/pil/): Required by plugin "graphs.py" (command 'binvi').
  * [PyGtk](http://www.pygtk.org/): Required by plugin "graphs.py" (command 'cgraph').