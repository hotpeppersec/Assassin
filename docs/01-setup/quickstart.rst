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

Run the Assassin Tool
---------------------

.. code-block:: bash

    make docker
    cd assassin
    python assassin.py
