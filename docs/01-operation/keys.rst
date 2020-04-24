====
Keys
====

There is a template `apiKeys.py` file that can be populated
with various keys to improve the functionality of the tool 
and the granularity of the report.


Shodan
------

The tool will check for the existence of an environment variable
containing the value of the Shodan key. For example:

.. code-block:: bash

    export SHODAN_KEY=`abc123keystringValue`

If this is not found, the tool will check for a value in the 
`apiKeys.py` file. Failing this, the tool will log an exception
and move on. No Shodan report will be generated for hosts
within the domain.


Google Maps
-----------

The tool will check for the existence of an environment variable
containing the value of the Google Maps key. For example:

.. code-block:: bash

    export GOOGLE_MAPS_KEY=`abc123keystringValue`

If this is not found, the tool will check for a value in the 
`apiKeys.py` file. Failing this, the tool will log an exception
and move on. No Google map will be added to the top of the detail
report.