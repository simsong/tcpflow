To execute customizable python plugins:

1. Create a python script with the following properties:

	- The script contains one or more functions for tcpflow usage.
	- Each intended function must take a single string parameter.  
		This parameter will hold the contents of the application data captured by tcpflow.
  - If an intended function returns, it must return a string,  
    which will then be added to the report.xml file with the "plugindata" tag.

2. Add the script to the `tcpflow/python/plugins` directory.

3. Execute the `tcpflow` command line with argument `-P ScriptName::FunctionName`.  
   Example:

	    tcpflow -r my.cap -o flows -P samplePlugin::sampleFunction
