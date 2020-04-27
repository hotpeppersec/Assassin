=====================
Assasin Local Dev Env
=====================

Testing
-------

Test cases are located in the /test folder. Test-specific Python3 modules,
to be installed in the docker container 
are listed in `/requirements-test.txt`. This includes the tox and coverage 
modules. The Dockerfile specifies a recent version of Python 3.x.

Disable Global Protect
----------------------

If the operator runs the tool with Global Protect enabled, the Shodan 
portion of the tool is blocked as described in the troubleshooting section. 

- The console will show HTTP 503 errors.
- The report output will be incomplete.

Running Test Suite Manually
---------------------------

Use the Makefile options to start the Docker container and execute the 
test suite.

.. code-block:: bash

    make docker
    make test

You should run the command `docker system prune` occasionally to free up 
space on your filesystem.

Automated Testing
-----------------

The file `/.github/workflows/python.yml` is the CI test configuration for 
GitHub Actions. This workflow will install Python dependencies, run tests 
and lint with a single version of Python (currently 3.8).

Test runs can be viewed (and reviewed for Pull Request errors)
by `clicking this link`_.

.. _clicking this link: https://github.com/wwce/Assassin/actions?query=workflow%3A%22Assassin+application%22