***************
Getting Started
***************

Installing
==========

Gene engine is a single executable without dependency. You can download the
latest releases for your OS from our `Github <https://github.com/0xrawsec/gene/releases>`_

Basic Usage
-----------

.. code-block:: bash

  # Assuming ./gene-rules is a directory containing your rules
  # Verifying that the rules are valid
  gene -r ./gene-rules -verify

  # Scanning a single file
  gene -r ./gene-rules -progress sysmon.evtx

  # Scanning several files
  gene -r ./gene-rules -progress *.evtx

  # Scanning Windows Events in JSON format (as printed by evtxdump)
  gene -r ./gene-rules -progress -j sysmon.json

  # Reading JSON Events from stdin
  cat some-events.json | gene -r ./gene-rules -progress -j -

  # Scan Events and set blacklist and whitelist containers
  gene -r ./gene-rules -bl blacklist.txt -wl whitelist.txt -j sysmon.json


WHIDS or how to use Gene in real time
=====================================

As Gene engine, WHIDS is a standalone executable that you can download on our
`dedicated Github <https://github.com/0xrawsec/whids/releases>`_. This tool is
a powerful Host IDS built on top of Gene engine and capable of analyzing many
events per seconds while taking limited resources.

If you just want to test WHIDS, you can do it in a second by simply downloading and executing
`trial.ps1 <https://raw.githubusercontent.com/0xrawsec/whids/master/trial.ps1>`_

Basic Usage
-----------

.. code-block:: powershell

  # WHIDS expects to listen directly on Windows Log Channel
  # but some aliases are hardcoded to prevent typing long Channel names
  # To make WHIDS listening on Sysmon Channel
  .\whids.exe -r ./gene-rules -c sysmon

  # To listen on both Sysmon and Security Channel and match event in real time
  .\whids.exe -r ./gene-rules -c "sysmon,security"

  # To listen on all aliased Windows Channels
  .\whids.exe -r ./gene-rules -c all

  # Download latest version of rule repository and use it
  .\whids.exe -u -c all

  # Log alerts to Windows Application log Channel
  .\whids.exe -r ./gene-rules -winlog -c all

  # Enable Windows Client-DNS logs and monitor according Channel
  .\whids.exe -r ./gene-rules -dns -c dns


Where do I find rules?
======================

We are maintaining a repository of rules, so feel free to download it `there <https://github.com/0xrawsec/gene-rules>`_
and use it.
