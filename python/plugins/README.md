To execute customizable python plugins:

1. Check examples in directory `tcpflow/python/plugins`.

2. Create a python script with the following properties:

  - The script contains one or more functions for tcpflow usage.
  - Each intended function must take a single string parameter.  
    This parameter will hold the contents of the application data captured by tcpflow.
  - If an intended function returns, it must return a string,  
    which will then be added to the report.xml file with the "plugindata" tag.

3. Execute the `tcpflow` command line with arguments `-e python -S pyPath=path -S pyModule=module -S pyFunction=foo`.  
   Example:

	    tcpflow -r my.cap -o flows -e python -S pyPath=python/plugins -S pyModule=samplePlugin -S pyFunction=sampleFunction
