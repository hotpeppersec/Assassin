=========
Operation
=========

Docker
------

While this tool can be run by installing the dependent Python3 modules to
your local machine, it is design so you can install Docker and run the tool 
inside a container. The goal is to prevent issues with differing Python 2 & 3 
versions, as well as possible dependency issues.

You can install Docker to your local machine by `clicking this link`_.

.. _clicking this link: https://docs.docker.com/get-docker/

Make
----

For ease of operation, this is a Makefile driven project. Once you've
installed Docker, type the command `make` to show the options available.

.. code-block:: bash

    user@host: ~ 🐦  make
    clean                Cleanup all the things
    docker               build docker container for testing
    docs                 Generate documentation
    python               setup python3
    test                 run tests in container

    Use the command `make docker` to set up the container.

Running Scans
-------------

To run the detail and summary reports for a domain, change to the 
/app/assassin directory and run the tool. 

.. code-block:: bash

    user@host: ~ 🐦  make docker
    Successfully built f591a2044610
    Successfully tagged docker_assassin:latest
    root@assassin:/app# cd assassin
    root@assassin:/app/assassin# python assassin.py --domain paloaltonetworks.com

If you do not pass the `--domain` flag you will be prompted 
to manually enter a domain. 

.. code-block:: bash

    root@assassin:/app/assassin# python assassin.py 
    Signatures loaded
    What domain would you like to search ? paloaltonetworks.com

Logging
-------

The tool is configured to write a log file to 
`/var/log/secops/assassin.log`. See the 
troubleshooting section for more details. 