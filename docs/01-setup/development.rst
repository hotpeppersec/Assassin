=====================
Assasin Local Dev Env
=====================

Testing
-------

Test cases are located in the /test folder. Test-specific
Python modules to be installed in the docker container
are listed in `/requirements-test.txt`. The Dockerfile
specifies a recent version of Python 3.x.

Disable Global Protect
----------------------

If the operator runs the tool with Global Protect enabled, 
the Shodan portion of the tool is blocked. 

- The console will show HTTP 503 errors.
- The report output will be incomplete.

Running Test Suite Manually
---------------------------

Use the Makefile options to start the Docker container
and execute the test suite.

.. code-block:: bash

    make docker
    make test

Automated Testing
-----------------

The file `/.github/workflows/python.yml` is the CI test
configuration for GitHub Actions. This workflow will 
install Python dependencies, run tests and lint with a 
single version of Python (currently 3.8).

Test runs can be viewed (and reviewed for Pull Request errors)
by clicking this link._

.. ._link: https://github.com/wwce/Assassin/actions?query=workflow%3A%22Assassin+application%22