==================
Quickstart for Mac
==================

Install brew
------------

``https://docs.brew.sh/Installation``

.. code-block:: bash

    mkdir homebrew && curl -L https://github.com/Homebrew/brew/tarball/master|tar xz --strip 1 -C homebrew
    brew tap caskroom/cask

Install Git
-----------

.. code-block:: bash

    brew install git


Install Docker Desktop
----------------------

Install Docker on MAC: overview_.

.. _overview: https://docs.docker.com/docker-for-mac/install/

Download the software package here_.

.. _here: https://hub.docker.com/editions/community/docker-ce-desktop-mac/


Configure "apiKeys.py"
----------------------

- Edit the file assassin/apiKey.py
- Change default values of apiKeys.py 
- Save file with update API key values
- Do not commit your API keys to the repo

.. code-block:: bash

    vtKey = 'CHANGEME'
    shodanKey = 'CHANGEME'
    GoogleMapsKey = 'CHANGEME'
    dnsdbKey = 'CHANGEME'
    GoogleSafeBrowsingKey = 'CHANGEME'

Disable Global Protect
----------------------

If the operator runs the tool with Global Protect enabled, 
the Shodan portion of the tool is blocked. 

- The console will show HTTP 503 errors.
- The report output will be incomplete.

Run the Assassin Tool
---------------------

.. code-block:: bash

    make docker
    cd assassin
    python assassin.py

Viewing Reports
---------------

Two `.html` files (a detail file and a summary file) will be
written to /app/assassin directory with the results of your
scans. These files should persist even if the operator exits
the Docker container. 

To remove these files, execute the `make clean` option from 
the top level of the repo directory.