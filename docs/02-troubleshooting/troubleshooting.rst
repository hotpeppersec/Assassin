===============
Troubleshooting
===============

Debug Logging
-------------

Debug level logging can be enabled for the tool. The results
will be written to the file `/var/log/secops/assassin.py`. 

Shodan Errors
-------------

- Shodan error: HTTP Error 404: Not Found
  - If you see `Processing host:` followed by a 404 error from Shodan, this means there is a DNS entry but the host is not up or does not exist.
- Shodan error: HTTP Error 503: Service Unavailable
  - Try disabling Global Protect


Reporting Issues/Requesting Help
--------------------------------

Please use the issues._ tab in the GitHub repo for this tool 
to report issues. Include a detailed description of the problem
as well as the debug log referenced above. 

.. issues._: https://github.com/wwce/Assassin/issues